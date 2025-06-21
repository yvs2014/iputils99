
alias test := test-raw

icmp_prop  := "net.ipv4.ping_group_range"
gr_min     := "0"
gr_max     := "21474836472"
icmp_req   := ">>> ICMP ping needs '" + gr_min + " " + gr_max + "' in 'sysctl " + icmp_prop + "'"

build:
	test -d _build || meson setup _build
	meson compile -C _build

clean:
	rm -rf _build

test-raw: build
	sudo setcap cap_net_raw+p ./_build/ping/ping
	meson test -C _build

test-icmp: build
	@sysctl {{icmp_prop}} | grep -q '[[:blank:]]=[[:blank:]]{{gr_min}}[[:blank:]]{{gr_max}}$' || \
		(echo "{{icmp_req}}"; exit 1;)
	meson test -C _build

