# Cookbook:: firewall
# Provider:: config

include Firewall::Helpers

action :add do
  sync_ip = new_resource.sync_ip
  ip_addr = new_resource.ip_addr
  flow_sensors = new_resource.flow_sensors || []
  flow_sensor_in_proxy_nodes = new_resource.flow_sensor_in_proxy_nodes || []
  ip_address_ips_nodes = get_ip_of_manager_ips_nodes
  vault_sensor_in_proxy_nodes = new_resource.vault_sensor_in_proxy_nodes || []
  all_managed_rich_rules = Hash.new { |hash, key| hash[key] = [] }

  dnf_package 'firewalld' do
    action :upgrade
  end

  service 'firewalld' do
    service_name 'firewalld'
    supports status: true, reload: true, restart: true, start: true, enable: true
    action [:enable, :start]
  end

  template '/etc/firewalld.conf' do
    source 'firewalld.conf.erb'
    cookbook 'rb-firewall'
    notifies :restart, 'service[firewalld]', :delayed
  end

  # Add sync interface and subnet to home zone
  if is_manager?
    sync_interface = interface_for_ip(sync_ip)
    sync_subnet = ip_to_subnet(sync_ip)

    firewall_rule 'Add sync interface to home' do
      interface sync_interface
      zone 'home'
      action :create
      permanent true
      not_if "firewall-cmd --zone=home --query-interface=#{sync_interface}"
      notifies :reload, 'service[firewalld]', :delayed
    end

    firewall_rule 'Add sync subnet to home' do
      sources sync_subnet
      zone 'home'
      action :create
      permanent true
      not_if "firewall-cmd --zone=home --query-source=#{sync_subnet}"
      notifies :reload, 'service[firewalld]', :delayed
    end
  end

  roles = {
    'manager' => %w(home public libvirt),
    'proxy' => %w(public),
    'ips' => %w(public),
  }
  roles.each do |role, zones|
    next unless send("is_#{role}?")
    zones.each do |zone|
      zone_rules = node['firewall']['roles'][role][zone].to_hash
      next if zone_rules.nil?
      all_managed_rich_rules[zone].concat(zone_rules['rich_rules'] || [])

      existing_tcp_ports, existing_udp_ports = get_existing_ports_in_zone(zone)
      existing_protocols = get_existing_protocols_in_zone(zone)

      Array(zone_rules['tcp_ports']).each do |port|
        apply_rule(:port, { port: port, action: :create }, zone, 'tcp') unless existing_tcp_ports.include?(port.to_s)
      end
      Array(zone_rules['udp_ports']).each do |port|
        apply_rule(:port, { port: port, action: :create }, zone, 'udp') unless existing_udp_ports.include?(port.to_s)
      end
      Array(zone_rules['protocols']).each do |protocol|
        unless existing_protocols.include?(protocol)
          apply_rule(:protocol, { protocol: protocol, action: :create }, zone)
        end
      end

      # Remove firewall ports and protocols that aren't in the attributes/default.rb zone rules
      allowed_tcp = (zone_rules['tcp_ports'] || []).map(&:to_s)
      Array(existing_tcp_ports).each do |port|
        apply_rule(:port, { port: port.to_i, action: :delete }, zone, 'tcp') unless allowed_tcp.include?(port)
      end
      allowed_udp = (zone_rules['udp_ports'] || []).map(&:to_s)
      Array(existing_udp_ports).each do |port|
        apply_rule(:port, { port: port.to_i, action: :delete }, zone, 'udp') unless allowed_udp.include?(port)
      end
      allowed_protocols = zone_rules['protocols'] || []
      Array(existing_protocols).each do |protocol|
        apply_rule(:protocol, { protocol: protocol, action: :delete }, zone) unless allowed_protocols.include?(protocol)
      end
    end
  end

  if is_manager? && sync_ip != ip_addr
    port = 9092 # Kafka
    allowed_addresses = ip_address_ips_nodes.empty? ? [] : ip_address_ips_nodes.map { |ips| ips[:ipaddress] }
    allowed_addresses.each do |ip|
      all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
    end
  end

  # Vault
  if is_proxy?
    port = 514
    allowed_addresses = get_ips_allowed_for_syslog_in_proxy(vault_sensor_in_proxy_nodes)
    allowed_addresses.each do |ip|
      all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"tcp\" accept"
      all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
    end
  elsif !is_ips?
    port = 514
    query = 'role:manager OR role:vault-sensor'
    allowed_nodes = search(:node, query).reject { |n| n['ipaddress'] == ip_addr }.sort_by(&:name)
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
    allowed_addresses = get_ips_allowed_for_sflow(flow_sensors, flow_sensor_in_proxy_nodes, ip_addr)
    allowed_addresses.each do |ip|
      all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
    end
  end
  if is_proxy?
    port = 6343
    allowed_addresses = get_ips_allowed_for_sflow_in_proxy(flow_sensor_in_proxy_nodes)
    allowed_addresses.each do |ip|
      all_managed_rich_rules['public'] << "rule family=\"ipv4\" source address=\"#{ip}\" port port=\"#{port}\" protocol=\"udp\" accept"
    end
  end

  all_managed_rich_rules.each do |zone, final_rules|
    final_rich_rules_list = final_rules.uniq
    existing_perm_rules = get_existing_rules_in_zone(zone)

    (final_rich_rules_list - existing_perm_rules).each do |rule|
      apply_rule(:rich_rule, { rule: rule, action: :create }, zone)
    end
    (existing_perm_rules - final_rich_rules_list).each do |rule|
      apply_rule(:rich_rule, { rule: rule, action: :delete }, zone)
    end
  end

  if is_manager?
    white_networks = Array(node.dig('redborder', 'white_networks')).map { |h| h['network'].to_s }
    black_networks = Array(node.dig('redborder', 'black_networks')).map { |h| h['network'].to_s }
    existing_white_networks = get_existing_sources('trusted')
    existing_black_networks = get_existing_sources('block')

    (white_networks - existing_white_networks).each do |network|
      apply_rule(:network, { network: network, action: :create }, 'trusted')
    end
    (existing_white_networks - white_networks).each do |network|
      apply_rule(:network, { network: network, action: :delete }, 'trusted')
    end
    (black_networks - existing_black_networks).each do |network|
      apply_rule(:network, { network: network, action: :create }, 'block')
    end
    (existing_black_networks - black_networks).each do |network|
      apply_rule(:network, { network: network, action: :delete }, 'block')
    end
  end

  execute 'reload_firewalld' do
    command 'firewall-cmd --reload'
    only_if do
      # Compare public
      public_runtime = `firewall-cmd --zone=public --list-rich-rules`.strip
      public_permanent = `firewall-cmd --permanent --zone=public --list-rich-rules`.strip
  
      # Compare libvirt
      libvirt_runtime = `firewall-cmd --zone=libvirt --list-ports`.strip
      libvirt_permanent = `firewall-cmd --permanent --zone=libvirt --list-ports`.strip
  
      # If there is a difference in any of the areas: reload
      (public_runtime != public_permanent) || (libvirt_runtime != libvirt_permanent)
    end
    action :run
  end

  Chef::Log.info('Firewall configuration has been applied.')
end

action :remove do
  service 'firewalld' do
    action [:disable, :stop]
  end

  Chef::Log.info('Firewall configuration has been removed.')
end

action :cleanup_virtual_ip_rules do
  if is_manager?
    previous_nginx_vip = new_resource.previous_nginx_vip
    current_nginx_vip = new_resource.current_nginx_vip
    manager_services = new_resource.manager_services || {}

    if previous_nginx_vip && (previous_nginx_vip != current_nginx_vip || !manager_services['keepalived'] || !manager_services['nginx'])
      execute 'remove_old_webui_iptables_rule' do
        command "iptables -t nat -D PREROUTING -d #{previous_nginx_vip} -j REDIRECT"
        only_if "iptables -t nat -C PREROUTING -d #{previous_nginx_vip} -j REDIRECT"
        ignore_failure true
      end
    end
  end
end
