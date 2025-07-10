from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('', views.home, name='home'),
    path('users/', views.users, name='users'),
    path('monitoring/', views.monitoring, name='monitoring'),
    path('server/', views.server_control, name='server_control'),
    path('notifications/', views.notifications, name='notifications'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('api/monitoring/', views.monitoring_api, name='monitoring_api'),
] 