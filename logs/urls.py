from django.urls import path
from . import views

app_name = 'logs'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('upload/', views.upload_logs, name='upload_logs'),
    path('alerts/', views.view_alerts, name='view_alerts'),
    path('alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('stats/', views.log_stats, name='log_stats'),
]
