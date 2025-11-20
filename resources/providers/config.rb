# Cookbook:: firewall
# Provider:: config

include Firewall::Helpers

action :add do
  sync_ip = new_resource.sync_ip

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

  # Single source of truth for all firewall rich rules
  converge_rich_rules

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
