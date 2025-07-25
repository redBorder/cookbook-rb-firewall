default['firewalld']['user'] = 'firewall'

default['firewall']['roles'] = {
  'manager' => {
    'home' => {
      'tcp_ports' => [
        53, 80, 443, 514, 2056,
        2057, 2058, 2181, 2888, 3888,
        4443, 5432, 7946, 7980, 8001,
        8080, 8081, 8082, 8083,
        8089, 8090, 8091, 8300, 8301,
        8302, 8400, 8500, 8888, 9000,
        9001, 9092, 11211, 50505
      ],
      'udp_ports' => [53, 123, 161, 162, 514, 1812, 1813, 2055, 5353, 6343, 7946, 8301, 8302, 11211],
      'protocols' => %w(igmp 112),
      'rich_rules' => ['rule family="ipv4" source address="224.0.0.18" accept'],
    },
    'public' => {
      'tcp_ports' => [80, 443, 2056, 2057, 2058, 7779],
      'udp_ports' => [123, 161, 162, 1812, 1813, 2055, 5353],
      'protocols' => ['112'],
      'rich_rules' => ['rule family="ipv4" source address="224.0.0.18" accept'],
    },
  },
  'proxy' => {
    'public' => {
      'tcp_ports' => [2056, 2057, 2058, 7779],
      'udp_ports' => [161, 162, 1812, 1813, 2055],
    },
  },
  'ips' => {
    'public' => {
      'udp_ports' => [161, 162],
    },
  },
}
