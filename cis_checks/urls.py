from django.conf.urls import url, include
from .views import viewOperations

urlpatterns = [
    url(r'^$', viewOperations.index),
    url(r'^givenKey/', viewOperations.enterDetails),
]