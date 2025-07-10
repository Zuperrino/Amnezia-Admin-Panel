from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import metrics_history_api, add_user, delete_user_view, deactivate_user_view

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('', views.home, name='home'),
    path('users/', views.users, name='users'),
    path('monitoring/', views.monitoring, name='monitoring'),
    path('server/', views.server_control, name='server_control'),
    path('notifications/', views.notifications, name='notifications'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('api/monitoring/', views.monitoring_api, name='monitoring_api'),
    path('api/metrics_history/', metrics_history_api, name='metrics_history_api'),
    path('api/events_history/', views.events_history_api, name='events_history_api'),
    path('add_user/', add_user, name='add_user'),
    path('delete_user/', delete_user_view, name='delete_user'),
    path('deactivate_user/', deactivate_user_view, name='deactivate_user'),
] 