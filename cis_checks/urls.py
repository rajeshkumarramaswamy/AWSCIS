from django.conf.urls import url, include
from .views import viewOperations

urlpatterns = [
    url(r'^$', viewOperations.index),
    url(r'^vue/', viewOperations.vuebase, name='vue'),
    url(r'^givenKey/', viewOperations.enterDetails),
    url(r'^vueFormSubmit/', viewOperations.vueFormSubmit),
    
]