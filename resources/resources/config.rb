# Cookbook:: firewall
#
# Resource:: config
#

unified_mode true
actions :add, :remove
default_action :add

attribute :user, kind_of: String, default: 'firewall'
property :vault_sensors, Array, required: false
property :vault_sensor_in_proxy_nodes, Array, required: false
property :sync_ip, String, required: false
property :ip_addr, String, required: false
