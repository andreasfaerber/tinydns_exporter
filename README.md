# tinydns_exporter
Simple server that reads tinydns statistics (requires tinystats installed) and exports them via HTTP for prometheus.

Find tinystats here: http://www.morettoni.net/tinystats.en.html

Installation:

```bash
git clone https://github.com/andreasfaerber/tinydns_exporter.git
cd tinydns_exporter
make
```

To run it:

```bash
./tinydns_exporter [flags]
```

Help on flags:
```bash
./tinydns_exporter --help
```
