from django.urls import path
from django.conf.urls import url, include

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.DetailView.as_view(), name='detail'),
    path('<int:pk>/vote/', views.VoteView.as_view(), name='vote'),
    url(r"logout/$", views.logout, name="logout"),
]
