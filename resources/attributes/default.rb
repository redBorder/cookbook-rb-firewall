default['firewalld']['user'] = 'firewall'

# Define roles with their respective firewall rules
default['firewall']['roles'] = {
  'manager' => {
    'home_zone' => {
      'tcp_ports' => [
        53, 443, 2056, 2057, 2058, 2181, 2888, 3888, 4443,
        5432, 7946, 7980, 8080, 8081, 8083, 8084, 8300, 8301,
        8302, 8400, 8500, 9000, 9001, 9092, 27017, 50505],
      'udp_ports' => [123, 161, 162, 1812, 1813, 2055, 5353, 6343],
      'protocols' => ['igmp'],
    },
    'public_zone' => {
      'tcp_ports' => [53, 443, 2056, 2057, 2058, 8080, 8081, 8083, 8084, 9000, 9001],
      'udp_ports' => [53, 161, 162, 123, 2055, 6343, 5353],
      'protocols' => ['112'],
      'rich_rules' => ['rule family="ipv4" source address="224.0.0.18" accept'],
    },
  },
  'proxy' => {
    'public_zone' => {
      'tcp_ports' => [514, 2056, 2057, 2058, 7779],
      'udp_ports' => [161, 162, 1812, 1813, 2055, 6343],
    },
  },
  'ips' => {
    'public_zone' => {
      'udp_ports' => [161, 162],
    },
  },
}