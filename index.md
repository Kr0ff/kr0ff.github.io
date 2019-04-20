---
layout: default
---

# $ cat posts.txt
{:id="posts"}

<ul>
{% for post in site.categories.posts %}

<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">{{ post.title }}</a></li>

{% endfor %}
</ul>

# $ more htb.txt
{:id="htb"}

<ul>
{% for post in site.categories.htb %}

<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">{{ post.title }}</a></li>

{% endfor %}
</ul>

# $ more vulnhub.txt
{:id="vulnhub"}

<ul>
{% for post in site.categories.vulnhub %}

<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">{{ post.title }}</a></li>

{% endfor %}
</ul>