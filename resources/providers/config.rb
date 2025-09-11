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

  # Applying firewall ports, protocols, and rich rules based on zones
  roles = {
    'manager' => %w(home public),
    'proxy' => %w(public),
    'ips' => %w(public),
  }
  roles.each do |role, zones|
    next unless send("is_#{role}?")

    zones.each do |zone|
      zone_rules = node['firewall']['roles'][role][zone]
      next if zone_rules.nil?

      existing_tcp_ports, existing_udp_ports = get_existing_ports_in_zone(zone)
      existing_protocols = get_existing_protocols_in_zone(zone)
      existing_rules = get_existing_rules_in_zone(zone)
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
      Array(zone_rules['rich_rules']).each do |rule|
        apply_rule(:rich_rule, { rule: rule, action: :create }, zone) unless existing_rules.include?(rule)
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
    # Managing port 9092 on the manager only for that specific IPS
    port = 9092 # kafka
    existing_addresses = get_existing_ip_addresses_in_rules(port).uniq
    allowed_addresses = ip_address_ips_nodes.empty? ? [] : ip_address_ips_nodes.map { |ips| ips[:ipaddress] }

    (existing_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Kafka', port: port, ip: ip, action: :delete }, 'public', 'tcp')
    end

    (allowed_addresses - existing_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Kafka', port: port, ip: ip, action: :create }, 'public', 'tcp')
    end

    # Managing port 8478 on the manager only for other managers in the public zone
    port = 8478 # redborder-cep
    existing_addresses = get_existing_ip_addresses_in_rules(port).uniq
    query = 'role:manager'
    allowed_nodes = search(:node, query).reject { |node| node['ipaddress'] == ip_addr }.sort_by(&:name)
    allowed_addresses = allowed_nodes.map { |node| node['ipaddress'] }
    target_addresses = allowed_addresses.empty? ? [] : allowed_addresses

    (existing_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'CEP', port: port, ip: ip, action: :delete }, 'public', 'tcp')
    end

    (allowed_addresses - existing_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'CEP', port: port, ip: ip, action: :create }, 'public', 'tcp')
    end
  end

  # Managing port 514 on the manager only for vault sensors, managers, ips and proxies
  if is_proxy?
    port = 514
    existing_tcp_addresses = get_existing_ip_addresses_in_rules(port, 'tcp')
    allowed_addresses = get_ips_allowed_for_syslog_in_proxy(vault_sensor_in_proxy_nodes)

    (existing_tcp_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'tcp')
    end
    (allowed_addresses - existing_tcp_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'tcp')
    end

    existing_udp_addresses = get_existing_ip_addresses_in_rules(port, 'udp')
    (existing_udp_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'udp')
    end
    (allowed_addresses - existing_udp_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'udp')
    end
  elsif !is_ips?
    port = 514
    query = 'role:manager OR role:vault-sensor'
    allowed_nodes = search(:node, query).reject { |node| node['ipaddress'] == ip_addr }.sort_by(&:name)
    allowed_addresses = allowed_nodes.select { |n| n['redborder']['parent_id'].nil? }
                                     .map { |n| n['ipaddress'] }
    target_addresses = allowed_addresses.empty? ? [] : allowed_addresses

    existing_tcp_addresses = get_existing_ip_addresses_in_rules(port, 'tcp')
    (existing_tcp_addresses - target_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'tcp')
    end
    (allowed_addresses - existing_tcp_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'tcp')
    end

    if is_manager?
      existing_udp_addresses = get_existing_ip_addresses_in_rules(port, 'udp')
      (existing_udp_addresses - target_addresses).each do |ip|
        apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'udp')
      end
      (allowed_addresses - existing_udp_addresses).each do |ip|
        apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'udp')
      end
    end
  end

  # Allowing sFlow traffic only for the IP sending sFlow
  if is_manager?
    port = 6343
    existing_addresses = get_existing_ip_addresses_in_rules(port).uniq
    allowed_addresses = get_ips_allowed_for_sflow(flow_sensors, flow_sensor_in_proxy_nodes, new_resource.ip_addr)

    (existing_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'sFlow', port: port, ip: ip, action: :delete }, 'public', 'udp')
    end

    (allowed_addresses - existing_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'sFlow', port: port, ip: ip, action: :create }, 'public', 'udp')
    end
  end

  # Allowing sFlow traffic only for the IP sending sFlow in the proxy
  if is_proxy?
    port = 6343
    existing_addresses = get_existing_ip_addresses_in_rules(port).uniq
    allowed_addresses = get_ips_allowed_for_sflow_in_proxy(flow_sensor_in_proxy_nodes)

    (existing_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'sFlow', port: port, ip: ip, action: :delete }, 'public', 'udp')
    end

    (allowed_addresses - existing_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'sFlow', port: port, ip: ip, action: :create }, 'public', 'udp')
    end
  end

  # Reload firewalld only if the runtime rules are different than the permanent rules
  # (a rule has been added/deleted and the service needs to be reloaded)
  execute 'reload_firewalld' do
    command 'firewall-cmd --reload'
    only_if do
      runtime_rules = `firewall-cmd --zone=public --list-rich-rules`.strip
      permanent_rules = `firewall-cmd --permanent --zone=public --list-rich-rules`.strip
      runtime_rules != permanent_rules
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
    previous_webui_vip = new_resource.previous_webui_vip
    current_webui_vip = new_resource.current_webui_vip
    manager_services = new_resource.manager_services || {}

    if previous_webui_vip && (previous_webui_vip != current_webui_vip || !manager_services['webui'])
      execute 'remove_old_webui_iptables_rule' do
        command "iptables -t nat -D PREROUTING -d #{previous_webui_vip} -j REDIRECT"
        only_if "iptables -t nat -C PREROUTING -d #{previous_webui_vip} -j REDIRECT"
        ignore_failure true
      end
    end
  end
end
