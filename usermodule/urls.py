from django.conf.urls import url
from . import views

app_name = 'music'

urlpatterns = [
    # templates for url
    # /music
    # url(r'^$', views.IndexView.as_view(), name='index'),

    # url(r'^register/$', views.UserFormView.as_view(), name='registration'),

    # /music/<album_id>
    url(r'^(?P<pk>[0-9]+)/$', views.DetailView.as_view(), name='detail'),

    # /music/album/add/
    # url(r'album/add/$', views.AlbumCreate.as_view(), name='album-add'),


]