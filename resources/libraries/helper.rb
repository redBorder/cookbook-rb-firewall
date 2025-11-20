module Firewall
  module Helpers
    require 'ipaddr'
    require 'socket'
    require 'json'
    include ::Chef::Mixin::ShellOut

    def valid_ip?(ip)
      IPAddr.new(ip)
      true
    rescue IPAddr::InvalidAddressError
      false
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
      end
    end

    def get_existing_ip_addresses_in_rules(port, protocol = nil)
      rules = shell_out!('firewall-cmd --permanent --zone=public --list-rich-rules').stdout.split("\n")

      filtered = rules.select do |rule|
        rule.include?("port port=\"#{port}\"") &&
          (protocol.nil? || rule.include?("protocol=\"#{protocol}\""))
      end

      filtered.map do |rule|
        match = rule.match(/source address="([^"]+)"/)
        match ? match[1] : nil
      end.compact.uniq
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
      rich_rules = shell_out!("firewall-cmd --permanent --zone=#{zone} --list-rich-rules").stdout
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
      proxy_uuids = flow_sensor_in_proxy_nodes.flat_map { |h| h.values.map { |v| v['sensor_uuid'] } }.compact
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

    def get_ips_allowed_for_syslog_in_proxy(vault_sensor_in_proxy_nodes)
      allowed_ips = []
      proxy_id = node['redborder']['sensor_id']

      (vault_sensor_in_proxy_nodes || []).each do |sensor_node|
        sensor_info = sensor_node.to_hash
        next unless sensor_info.is_a?(Hash)

        parent_id = sensor_info['redborder']['parent_id']
        ip = sensor_info['ipaddress']

        # Just add the IP if it matches the parent_id and is a valid IPv4 address
        if parent_id.to_i == proxy_id.to_i && ip =~ /^\d{1,3}(\.\d{1,3}){3}$/
          allowed_ips << ip
        else
          Chef::Log.warn(">> [Proxy] Sensor omitted: IP=#{ip.inspect}, parent_id=#{parent_id}")
        end
      end

      allowed_ips.uniq.compact
    end

    # Function to manage all rich rules from all sources in a unified way,
    # it helps with the problem of having multiple sources of rich rules.
    def converge_rich_rules
      all_managed_rich_rules = Hash.new { |hash, key| hash[key] = [] }

      roles = {
        'manager' => %w(home public),
        'proxy' => %w(public),
        'ips' => %w(public),
      }
      roles.each do |role, zones|
        next unless send("is_#{role}?")
        zones.each do |zone|
          zone_rules = node['firewall']['roles'][role][zone].to_hash
          next if zone_rules.nil?
          all_managed_rich_rules[zone].concat(zone_rules['rich_rules'] || [])
        end
      end

      whitelist_networks = node['redborder']['white_networks'] || []
      blacklist_networks = node['redborder']['black_networks'] || []
      whitelist_networks.each do |network|
        all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{network['network']}\" accept"
      end
      blacklist_networks.each do |network|
        all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{network['network']}\" reject"
      end

      if is_manager? && new_resource.sync_ip != new_resource.ip_addr
        port = 9092 # Kafka
        allowed_addresses = get_ip_of_manager_ips_nodes.empty? ? [] : get_ip_of_manager_ips_nodes.map { |ips| ips[:ipaddress] }
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
        end

        port = 8478 # CEP
        query = 'role:manager'
        allowed_nodes = search(:node, query).reject { |n| n['ipaddress'] == new_resource.ip_addr }.sort_by(&:name)
        allowed_addresses = allowed_nodes.map { |n| n['ipaddress'] }
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
        end
      end

      # Vault
      if is_proxy?
        port = 514
        allowed_addresses = get_ips_allowed_for_syslog_in_proxy(new_resource.vault_sensor_in_proxy_nodes)
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
        end
      elsif !is_ips?
        port = 514
        query = 'role:manager OR role:vault-sensor'
        allowed_nodes = search(:node, query).reject { |n| n['ipaddress'] == new_resource.ip_addr }.sort_by(&:name)
        allowed_addresses = allowed_nodes.select { |n| n['redborder']['parent_id'].nil? }.map { |n| n['ipaddress'] }
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
          if is_manager?
            all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
          end
        end
      end

      # sFlow
      if is_manager?
        port = 6343
        allowed_addresses = get_ips_allowed_for_sflow(new_resource.flow_sensors, new_resource.flow_sensor_in_proxy_nodes, new_resource.ip_addr)
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
        end
      end
      if is_proxy?
        port = 6343
        allowed_addresses = get_ips_allowed_for_sflow_in_proxy(new_resource.flow_sensor_in_proxy_nodes)
        allowed_addresses.each do |ip|
          all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
        end
      end

      all_managed_rich_rules.each do |zone, final_rules|
        final_rich_rules_list = final_rules.uniq
        puts ">> [Firewall] Final rich rules for zone #{zone}:"
        final_rich_rules_list.each do |rule|
          puts "   #{rule}"
        end
        existing_perm_rules = get_existing_rules_in_zone(zone)
        puts ">> [Firewall] Existing rich rules in zone #{zone}:"
        existing_perm_rules.each do |rule|
          puts "   #{rule}"
        end
        rules_to_add = final_rich_rules_list - existing_perm_rules
        puts ">> [Firewall] Rich rules to add in zone #{zone}:"
        rules_to_add.each do |rule|
          puts "   #{rule}"
        end
        rules_to_remove = existing_perm_rules - final_rich_rules_list
        puts ">> [Firewall] Rich rules to remove in zone #{zone}:"
        rules_to_remove.each do |rule|
          puts "   #{rule}"
        end

        rules_to_add.each do |rule|
          apply_rule(:rich_rule, { rule: rule, action: :create }, zone)
        end
        rules_to_remove.each do |rule|
          apply_rule(:rich_rule, { rule: rule, action: :delete }, zone)
        end
      end
    end
  end
end
