---
layout: default
---

<div class="htb-writeups">
    {% for writeup in site.htb-writeups %}
    <div class="htb-writeups_container">
        <a href="{{ site.baseurl }}/{{ site.htb-writeups">Testing this.</a>
        <div>
            {{ writeup.content }}   
        </div>
    </div>
    {% endfor %}
</div>