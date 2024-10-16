# Cookbook:: firewall
#
# Resource:: config
#

unified_mode true
actions :add, :remove
default_action :add

attribute :user, kind_of: String, default: 'firewall'
property :sync_ip, String, required: false
property :ip_addr, String, required: false
