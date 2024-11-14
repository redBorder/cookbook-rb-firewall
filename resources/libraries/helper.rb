module Firewall
  module Helpers
    require 'ipaddr'
    require 'socket'
    include ::Chef::Mixin::ShellOut

    def fetch_existing_rules(zone)
      ports = shell_out!("firewall-cmd --zone=#{zone} --list-ports").stdout.strip.split(/\s+/)
      protos = shell_out!("firewall-cmd --zone=#{zone} --list-protocols").stdout.strip.split(/\s+/)
      rich_rules = shell_out!("firewall-cmd --zone=#{zone} --list-rich-rules").stdout.strip.split(/\n/)
      return ports, protos, rich_rules
    end

    def configure_firewalld_rules
      if is_manager?
        ports_home, protos_home, rich_rules_home = fetch_existing_rules('home')
        apply_zone_rules(node['firewall']['roles']['manager']['home_zone'], 'home', ports_home, protos_home, rich_rules_home)

        ports_pub, protos_pub, rich_rules_pub = fetch_existing_rules('public')
        apply_zone_rules(node['firewall']['roles']['manager']['public_zone'], 'public', ports_pub, protos_pub, rich_rules_pub)
      end
      if is_proxy?
        ports_pub, protos_pub, rich_rules_pub = fetch_existing_rules('public')
        apply_zone_rules(node['firewall']['roles']['proxy']['public_zone'], 'public', ports_pub, protos_pub, rich_rules_pub)
      end
      if is_ips?
        ports_pub, protos_pub, rich_rules_pub = fetch_existing_rules('public')
        apply_zone_rules(node['firewall']['roles']['ips']['public_zone'], 'public', ports_pub, protos_pub, rich_rules_pub)
      end
    end

    def apply_zone_rules(zone_rules, zone, existing_ports, existing_protocols, existing_rich_rules)
      return if zone_rules.nil?
      zone_rules['tcp_ports']&.each { |port| apply_rule(:port, port, zone, existing_ports, 'tcp') }
      zone_rules['udp_ports']&.each { |port| apply_rule(:port, port, zone, existing_ports, 'udp') }
      zone_rules['protocols']&.each { |protocol| apply_rule(:protocol, protocol, zone, existing_protocols) }
      zone_rules['rich_rules']&.each { |rule| apply_rule(:rich_rule, rule, zone, existing_rich_rules) }
    end

    def apply_rule(type, value, zone, existing_items, protocol = nil)
      value = "#{value}/#{protocol || 'tcp'}" if type == :port
      unless existing_items.include?(value)
        case type
        when :port
          firewall_rule "Allow port #{value} in #{zone} zone" do
            port value
            protocol protocol
            zone zone
            action :create
            permanent true
          end
        when :protocol
          firewall_rule "Allow protocol #{value} in #{zone} zone" do
            protocols value
            zone zone
            action :create
            permanent true
          end
        when :rich_rule
          firewall_rule "Adding rich rule #{value} in #{zone} zone" do
            rules value
            zone zone
            action :create
            permanent true
          end
        end
      end
    end

    def manage_kafka_rule_for_ips(ip, rich_rules)
      unless rich_rules.include?(ip)
        firewall_rule "Open Kafka port 9092 for manager ips" do
          rules "rule family='ipv4' source address=#{ip} port port=9092 protocol=tcp accept"
          zone 'public'
          action :create
          permanent true
        end
      end
    end

    def remove_kafka_rule_for_ips(ip, rich_rules)
      if rich_rules.include?(ip)
        firewall_rule "Remove Kafka port 9092 for manager IPs" do
          rules "rule family='ipv4' source address=#{ip} port port=9092 protocol=tcp accept"
          zone 'public'
          action :delete
          permanent true
        end
      end
    end

    def reload!
      shell_out!('firewall-cmd --reload')
    end

    def get_existing_ips_for_port(rich_rules)
      existing_ips = []
      rich_rules.split("\n").each do |rule|
        if rule.include?('port="9092"')
          ip_match = rule.match(/source address="([^"]+)"/)
          existing_ips << ip_match[1] if ip_match
        end
      end
      existing_ips
    end

    def interface_for_ip(ip_address)
      return nil if ip_address.nil? || ip_address.empty?
      interfaces = Socket.getifaddrs
      interface = interfaces.find do |ifaddr|
        ifaddr.addr.ipv4? && ifaddr.addr.ip_address == ip_address
      end
      interface.name
    end

    def ip_to_subnet(ip_address, prefix = 24)
      ip = IPAddr.new(ip_address)
      subnet = ip.mask(prefix)
      "#{subnet}/#{prefix}"
    end

    def is_proxy?
      node.role?('proxy-sensor')
    end

    def is_manager?
      node.role?('manager')
    end

    def is_ips?
      node.role?('ips-sensor') || node.role?('ipscp-sensor')
    end

    def get_ip_of_manager_ips
      sensors = search(:node, 'role:ips-sensor').sort
      sensors.map { |s| { ipaddress: s['ipaddress'] } }
    end
  end
end
