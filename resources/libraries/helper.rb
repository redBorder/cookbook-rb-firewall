module Firewall
  module Helpers
    require 'ipaddr'
    require 'socket'
    include ::Chef::Mixin::ShellOut

    def apply_rule(type, value, zone, protocol = nil)
      case type
      when :port
        firewall_rule "Allow port #{value}/#{protocol} in #{zone} zone" do
          port value
          protocol protocol
          zone zone
          action :create
          permanent true
          not_if "firewall-cmd --permanent --zone=#{zone} --query-port=#{value}/#{protocol}"
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :protocol
        firewall_rule "Allow protocol #{value} in #{zone} zone" do
          protocols value
          zone zone
          action :create
          permanent true
          not_if "firewall-cmd --permanent --zone=#{zone} --query-protocol=#{value}"
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :rich_rule
        firewall_rule "Adding rich rule #{value} in #{zone} zone" do
          rules value
          zone zone
          action :create
          permanent true
          not_if "firewall-cmd --permanent --zone=#{zone} --query-rich-rule='#{value}'"
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :filter_by_ip
        name = value[:name]
        port = value[:port]
        ip = value[:ip]
        action = value[:action]
        rich_rule = "rule family='ipv4' source address='#{ip}' port port='#{port}' protocol='#{protocol}' accept"
        firewall_rule "#{action} #{name} port #{port}/#{protocol} for IP: #{ip}" do
          rules rich_rule
          action action
          permanent true
          if action == :create
            not_if "firewall-cmd --permanent --zone=#{zone} --query-rich-rule='#{rich_rule}'"
          else
            only_if "firewall-cmd --permanent --zone=#{zone} --query-rich-rule='#{rich_rule}'"
          end
        end
      end
    end

    def get_existing_ip_addresses_in_rules(port)
      rich_rules = shell_out!('firewall-cmd --zone=public --list-rich-rules').stdout
      existing_ips = []
      rich_rules.split("\n").each do |rule|
        if rule.include?("port=\"#{port}\"")
          ip_match = rule.match(/source address="([^"]+)"/)
          existing_ips << ip_match[1] if ip_match
        end
      end
      existing_ips
    end

    def interface_for_ip(ip_address)
      return if ip_address.nil? || ip_address.empty?
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

    def get_ip_of_manager_ips_nodes
      sensors = search(:node, 'role:ips-sensor').sort
      sensors.map { |s| { ipaddress: s['ipaddress'] } }
    end
  end
end
