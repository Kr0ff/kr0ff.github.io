---
layout: default
---

# $ cat posts.txt
{:id="posts"}

<ul>
{% for post in site.categories.posts %}

<li>{{ post.title }} :: <a href="{{ post.url }}" title="{{ post.description }}">Read</a></li>

{% endfor %}
</ul>