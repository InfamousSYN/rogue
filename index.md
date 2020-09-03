---
layout: default
title: Home
nav_order: 1
description: "The Rogue Toolkit Documentation"
permalink: /
---

# Rogue
{: .fs-9 }

An extensible toolkit providing penetration testers an easy-to-use platform to deploy Access Points during penetration testing and red team engagements. 
{: .fs-6 .fw-300 }

[Get started now](#getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 } [View it on GitHub](https://github.com/InfamousSYN/rogue){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## About

Forked from s0lst1c3's [eaphammer](https://github.com/s0lst1c3/eaphammer) project, The Rogue Toolkit is an extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy software-defined Access Points (AP) for the purpose of conducting wireless penetration testing and red team engagements. By using Rogue, penetration testers can easily perform targeted evil twin attacks against a variety of wireless network types. 

## Getting started

### Dependencies

Just the Docs is built for [Jekyll](https://jekyllrb.com), a static site generator. View the [quick start guide](https://jekyllrb.com/docs/) for more information. Just the Docs requires no special plugins and can run on GitHub Pages' standard Jekyll compiler. The [Jekyll SEO Tag plugin](https://github.com/jekyll/jekyll-seo-tag) is included by default (no need to run any special installation) to inject SEO and open graph metadata on docs pages. For information on how to configure SEO and open graph metadata visit the [Jekyll SEO Tag usage guide](https://jekyll.github.io/jekyll-seo-tag/usage/).

### Quick start:

1. Download [rogue](https://github.com/InfamousSYN/rogue) 
```
git clone https://github.com/InfamousSYN/rogue ; cd ./rogue
```
2. Run installer
```
python3 ./install.py
```
3. Run rogue
```
python3 rogue.py -i wlan0 -h g -c 6 -e rogue --auth open --internet
```

### Check out Rogue's capabilities

- [See utilities options]({{ site.baseurl }}{% link docs/utilities/utilities.md %})

---

## About the project

### License

Just the Docs is distributed by an [GNU GENERAL PUBLIC LICENSE v3](https://github.com/InfamousSYN/rogue/blob/master/LICENSE).
