# Cookbook:: firewall
# Provider:: config

include Firewall::Helpers

action :add do
  sync_ip = new_resource.sync_ip
  ip_addr = new_resource.ip_addr
  ip_address_ips_nodes = get_ip_of_manager_ips_nodes

  dnf_package 'firewalld' do
    action :upgrade
    flush_cache [:before]
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
      zone_rules['tcp_ports']&.each { |port| apply_rule(:port, port, zone, 'tcp') }
      zone_rules['udp_ports']&.each { |port| apply_rule(:port, port, zone, 'udp') }
      zone_rules['protocols']&.each { |protocol| apply_rule(:protocol, protocol, zone) }
      zone_rules['rich_rules']&.each { |rule| apply_rule(:rich_rule, rule, zone) }
    end
  end

  if is_manager? && sync_ip != ip_addr
    # Managing port 9092 on the manager only for that specific IPS
    port = 9092
    existing_addresses = get_existing_ip_addresses_in_rules(port)
    allowed_addresses = ip_address_ips_nodes.empty? ? existing_addresses : ip_address_ips_nodes.map { |ips| ips[:ipaddress] }

    (existing_addresses - allowed_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Kafka', port: port, ip: ip, action: :delete }, 'public', 'tcp')
    end

    allowed_addresses.each do |ip|
      apply_rule(:filter_by_ip, { name: 'Kafka', port: port, ip: ip, action: :create }, 'public', 'tcp')
    end
  end

  unless is_ips?
    # Managing port 514 on the manager only for vault sensors, managers, ips and proxies
    port = 514
    existing_addresses = get_existing_ip_addresses_in_rules(port).uniq
    query = 'role:ips-sensor OR role:proxy-sensor OR role:manager OR role:vault-sensor'
    allowed_nodes = search(:node, query).reject { |node| node['ipaddress'] == ip_addr }.sort_by { |node| node.name }
    allowed_addresses = allowed_nodes.map { |node| node['ipaddress'] }
    target_addresses = allowed_addresses.empty? ? existing_addresses : allowed_addresses

    (existing_addresses - target_addresses).each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'tcp')
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :delete }, 'public', 'udp')
    end

    target_addresses.each do |ip|
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'tcp')
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'public', 'udp')
    end

    if is_manager?
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'home', 'tcp')
      apply_rule(:filter_by_ip, { name: 'Vault', port: port, ip: ip, action: :create }, 'home', 'udp')
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
