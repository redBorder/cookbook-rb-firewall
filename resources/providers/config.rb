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

  # Managing port 9092 on the manager only for that specific IPS
  if is_manager? && sync_ip != ip_addr
    existing_addresses = get_existing_ip_addresses_in_rules
    aux = ip_address_ips_nodes.empty? ? existing_addresses : ip_address_ips_nodes.map { |ips| ips[:ipaddress] }

    unless ip_address_ips_nodes.empty?
      ips_to_remove = existing_addresses - aux
      ips_to_remove.each do |ip|
        firewall_rule "Remove Kafka port 9092 for IP: #{ip}" do
          rules "rule family='ipv4' source address=#{ip} port port=9092 protocol=tcp accept"
          zone 'public'
          action :delete
          permanent true
          only_if "firewall-cmd --permanent --zone=public --query-rich-rule='rule family=\"ipv4\" source address=\"#{ip}\" port port=\"9092\" protocol=\"tcp\" accept'"
          notifies :reload, 'service[firewalld]', :delayed
        end
      end
    end

    aux.each do |ip|
      firewall_rule "Open Kafka port 9092 for IP: #{ip}" do
        rules "rule family='ipv4' source address=#{ip} port port=9092 protocol=tcp accept"
        zone 'public'
        action :create
        permanent true
        not_if "firewall-cmd --permanent --zone=public --query-rich-rule='rule family=\"ipv4\" source address=\"#{ip}\" port port=\"9092\" protocol=\"tcp\" accept'"
        notifies :reload, 'service[firewalld]', :delayed
      end
    end
  end

  Chef::Log.info('Firewall configuration has been applied.')
end

action :remove do
  service 'firewalld' do
    action [:disable, :stop]
  end

  Chef::Log.info('Firewall configuration has been removed.')
end
