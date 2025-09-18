# Cookbook:: firewall
#
# Resource:: config
#

unified_mode true
actions :add, :remove, :cleanup_virtual_ip_rules
default_action :add

attribute :user, kind_of: String, default: 'firewall'
property :flow_sensors, Array, required: false
property :flow_sensor_in_proxy_nodes, Array, required: false
property :vault_sensors, Array, required: false
property :vault_sensor_in_proxy_nodes, Array, required: false
property :sync_ip, String, required: false
property :ip_addr, String, required: false
property :current_nginx_vip, kind_of: String, default: nil
property :previous_nginx_vip, kind_of: String, default: nil
property :manager_services, kind_of: Hash, default: {}
