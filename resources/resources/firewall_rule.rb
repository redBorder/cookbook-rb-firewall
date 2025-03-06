resource_name :firewall_rule
provides :firewall_rule

unified_mode true

property :port, kind_of: [Integer, Array, Range], required: false
property :protocol, kind_of: [String, Symbol], default: :tcp
property :zone, kind_of: String, default: 'public'
property :protocols, kind_of: String, required: false
property :rules, kind_of: [String, Array], required: false
property :interface, kind_of: String, required: false
property :sources, kind_of: String, required: false
property :permanent, kind_of: [TrueClass, FalseClass], default: true

action :create do
  extend Firewall::Helpers

  if shell_out!('firewall-cmd --state').stdout =~ /^running$/
    if new_resource.port
      Array(new_resource.port).each do |port|
        command = "firewall-cmd --zone=#{new_resource.zone} --add-port=#{port}/#{new_resource.protocol}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.protocols
      Array(new_resource.protocols).each do |prot|
        command = "firewall-cmd --zone=#{new_resource.zone} --add-protocol=#{prot}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.rules
      Array(new_resource.rules).each do |rule|
        command = "firewall-cmd --zone=#{new_resource.zone} --add-rich-rule='#{rule}'"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.interface
      Array(new_resource.interface).each do |inf|
        command = "firewall-cmd --zone=#{new_resource.zone} --add-interface=#{inf}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.sources
      Array(new_resource.sources).each do |src|
        command = "firewall-cmd --zone=#{new_resource.zone} --add-source=#{src}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end
  else
    Chef::Log.warn('firewalld is not running. Firewall rule will not be applied.')
  end
end

action :delete do
  extend Firewall::Helpers

  if shell_out!('firewall-cmd --state').stdout =~ /^running$/
    if new_resource.port
      Array(new_resource.port).each do |port|
        command = "firewall-cmd --zone=#{new_resource.zone} --remove-port=#{port}/#{new_resource.protocol}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.protocols
      Array(new_resource.protocols).each do |prot|
        command = "firewall-cmd --zone=#{new_resource.zone} --remove-protocol=#{prot}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.rules
      Array(new_resource.rules).each do |rule|
        command = "firewall-cmd --zone=#{new_resource.zone} --remove-rich-rule='#{rule}'"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.interface
      Array(new_resource.interface).each do |inf|
        command = "firewall-cmd --zone=#{new_resource.zone} --remove-interface=#{inf}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

    if new_resource.sources
      Array(new_resource.sources).each do |src|
        command = "firewall-cmd --zone=#{new_resource.zone} --remove-source=#{src}"
        command += ' --permanent' if new_resource.permanent
        shell_out!(command)
      end
    end

  else
    Chef::Log.warn('firewalld is not running. Firewall rule will not be applied.')
  end
end
