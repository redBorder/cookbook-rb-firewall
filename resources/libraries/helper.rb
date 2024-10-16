# Cookbook:: firewall
# Provider:: config

include Firewall::Helpers

action :add do
  sync_ip = new_resource.sync_ip
  ip_addr = new_resource.ip_addr
  ip_address_ips = get_ip_of_manager_ips

  service 'firewalld' do
    action [:enable, :start]
  end

  dnf_package 'firewalld' do
    action :upgrade
    flush_cache [:before]
  end

  template '/etc/firewalld.conf' do
    source 'firewalld.conf.erb'
    cookbook 'rb-firewall'
    notifies :restart, 'service[firewalld]', :delayed
  end

  if is_manager?
    sync_interface = interface_for_ip(sync_ip)
    sync_subnet = ip_to_subnet(sync_ip)
    interfaces = shell_out!('firewall-cmd --zone=home --list-interfaces').stdout.strip.split
    sources = shell_out!('firewall-cmd --zone=home --list-sources').stdout.strip.split

    unless interfaces.include?(interface_for_ip(sync_ip))
      firewall_rule 'Add sync interface to home' do
        interface sync_interface
        zone 'home'
        action :create
        permanent true
      end
    end

    unless sources.include?(ip_to_subnet(sync_ip))
      firewall_rule 'Add sync subnet to home' do
        sources sync_subnet
        zone 'home'
        action :create
        permanent true
      end
    end
  end

  configure_firewalld_rules

  if is_manager? && sync_ip != ip_addr
    rich_rules = shell_out!('firewall-cmd --zone=public --list-rich-rules').stdout
    existing_ips = get_existing_ips_for_port(rich_rules)

    if ip_address_ips.empty?
      existing_ips.each do |ip|
        if rich_rules.match(/source address=\"#{ip}\".*port port=\"9092\".*protocol=\"tcp\"/)
          remove_kafka_rule_for_ips(ip)
        end
      end
    else
      ips_to_remove = existing_ips - ip_address_ips.map { |ips| ips[:ipaddress] }
      ips_to_remove.each do |ip|
        if rich_rules.match(/source address=\"#{ip}\".*port port=\"9092\".*protocol=\"tcp\"/)
          remove_kafka_rule_for_ips(ip)
        end
      end
      ip_address_ips.each do |ip|
        unless rich_rules.match(/source address=\"#{ip[:ipaddress]}\".*port port=\"9092\".*protocol=\"tcp\"/)
          manage_kafka_rule_for_ips(ip[:ipaddress])
        end
      end
    end
  end

  reload!

  Chef::Log.info('Firewall configuration has been applied.')
end

action :remove do
  service 'firewalld' do
    action [:disable, :stop]
  end

  Chef::Log.info('Firewall configuration has been removed.')
end
