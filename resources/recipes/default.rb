# Cookbook:: rb-firewall
# Recipe:: default

# Call the firewall configuration
rb_firewall_config 'Configure Firewall' do
  action :add
end
