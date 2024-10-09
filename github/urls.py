from django.urls import path
from .views import list_codespaces,shutdown_codespace,view,logout_view,login_view,register_view,change_password_view,password_change_done_view

urlpatterns = [
    path('list-codespaces/',list_codespaces,name='list_codespaces'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('change_password/', change_password_view, name='change_password'),
    path('password_change_done/', password_change_done_view, name='password_change_done'),
    path('logout/', logout_view, name='logout'),  
    path('',view,name='home'),
    path('shutdown_codespace/', shutdown_codespace, name='shutdown_codespace'),

]