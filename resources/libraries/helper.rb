module Firewall
  module Helpers
    require 'ipaddr'
    require 'socket'
    require 'json'
    include ::Chef::Mixin::ShellOut

    def valid_ip?(ip)
      begin
        IPAddr.new(ip)
        true
      rescue IPAddr::InvalidAddressError
        false
      end
    end

    def apply_rule(type, value, zone, protocol = nil)
      case type
      when :port
        act = value[:action]
        firewall_rule "#{act} port #{value[:port]}/#{protocol} in #{zone} zone" do
          port value[:port]
          protocol protocol
          zone zone
          action act
          permanent true
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :protocol
        act = value[:action]
        firewall_rule "#{act} protocol #{value[:protocol]} in #{zone} zone" do
          protocols value[:protocol]
          zone zone
          action act
          permanent true
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :rich_rule
        act = value[:action]
        firewall_rule "#{act} rich rule #{value[:rule]} in #{zone} zone" do
          rules value[:rule]
          zone zone
          action act
          permanent true
          notifies :reload, 'service[firewalld]', :delayed
        end
      when :filter_by_ip
        act = value[:action]
        name = value[:name]
        port_val = value[:port]
        ip_val = value[:ip]

        unless valid_ip?(ip_val)
          Chef::Log.warn('Firewall rule will not be applied.')
          return
        end

        rich_rule = "rule family='ipv4' source address='#{ip_val}' port port='#{port_val}' protocol='#{protocol}' accept"
        firewall_rule "#{act} #{name} port #{port_val}/#{protocol} for IP: #{ip_val} in #{zone} zone" do
          rules rich_rule
          zone zone
          action act
          permanent true
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

    def get_existing_ports_in_zone(zone)
      ports = shell_out!("firewall-cmd --zone=#{zone} --list-ports").stdout
      existing_tcp_ports = []
      existing_udp_ports = []
      ports.split(' ').each do |port|
        port.split('/')
        existing_tcp_ports << port.split('/')[0] if port.include?('tcp')
        existing_udp_ports << port.split('/')[0] if port.include?('udp')
      end
      [existing_tcp_ports, existing_udp_ports]
    end

    def get_existing_protocols_in_zone(zone)
      protocols = shell_out!("firewall-cmd --zone=#{zone} --list-protocols").stdout
      existing_protocols = []
      protocols.split(' ').each do |protocol|
        existing_protocols << protocol
      end
      existing_protocols
    end

    def get_existing_rules_in_zone(zone)
      rich_rules = shell_out!("firewall-cmd --zone=#{zone} --list-rich-rules").stdout
      existing_rules = []
      rich_rules.split("\n").each do |rule|
        existing_rules << rule
      end
      existing_rules
    end

    def interface_for_ip(ip_address)
      return unless valid_ip?(ip_address)
      interfaces = Socket.getifaddrs
      interface = interfaces.find do |ifaddr|
        ifaddr.addr.ipv4? && ifaddr.addr.ip_address == ip_address
      end
      interface&.name
    end

    def ip_to_subnet(ip_address, prefix = 24)
      return unless valid_ip?(ip_address)
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
      sensors = search(:node, '(role:ips-sensor OR role:intrusion-sensor)').sort
      sensors.map { |s| { ipaddress: s['ipaddress'] } }
    end

    # Returns a list of IPs of sensors that are sending sFlow data to the local node.
    def get_ips_allowed_for_sflow(flow_sensors, flow_sensor_in_proxy_nodes, ip_addr)
      proxy_uuids = flow_sensor_in_proxy_nodes.map { |h| h.values.first['sensor_uuid'] }.compact
      allowed_ips = []

      flow_sensors.each do |node|
        uuid = node.dig('redborder', 'sensor_uuid') || node.dig('normal', 'redborder', 'sensor_uuid')
        ip = node['ipaddress'] ||
             node.dig('redborder', 'ipaddress') ||
             node.dig('normal', 'redborder', 'ipaddress')

        next if proxy_uuids.include?(uuid)

        if ip && ip.match?(/^\d{1,3}(\.\d{1,3}){3}$/) && ip != ip_addr
          allowed_ips << ip
        else
          Chef::Log.warn("Skipping node (#{node.name}) for sFlow - Invalid or duplicate IP: #{ip.inspect}")
        end
      end

      allowed_ips.uniq.compact
    end

    # Returns a list of IPs of flow sensors that are allowed to send sFlow to the proxy.
    def get_ips_allowed_for_sflow_in_proxy(flow_sensor_in_proxy_nodes)
      allowed_ips = []
      proxy_id = node['redborder']['sensor_id']
      (flow_sensor_in_proxy_nodes || []).each do |sensor_info|
        next unless sensor_info.is_a?(Hash)

        sensor_info.each do |_hostname, data|
          next unless data.is_a?(Hash)

          parent_id = data['parent_id']
          ip = data['ipaddress']

          # Just add the IP if it matches the parent_id and is a valid IPv4 address
          if parent_id.to_i == proxy_id.to_i && ip =~ /^\d{1,3}(\.\d{1,3}){3}$/
            allowed_ips << ip
          else
            Chef::Log.warn(">> [sFlow Proxy] Sensor omitido: IP=#{ip.inspect}, parent_id=#{parent_id}")
          end
        end
      end

      allowed_ips.uniq.compact
    end
  end
end
