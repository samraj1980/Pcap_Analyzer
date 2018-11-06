from django.conf.urls import url
from .import views

urlpatterns = [
    url(r'^$', views.index, name = 'index'),
    # url(r'^nofile.html/', views.nofiles, name = 'nofiles'),
 ]
