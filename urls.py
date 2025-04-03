from django.urls import path
from .views import login_view, logout_view, user_list_create, user_detail, photo_list, photo_detail,get_csrf_token, current_user, dashboard_stats, contact_view, update_info_view,update_password_view, my_photos_view, get_admin_info, update_profile_picture

urlpatterns = [
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('admin_info/', get_admin_info, name='admin_info'),
    path('update_profile_picture/', update_profile_picture, name='update_profile_picture'),
    path('dashboard_stats/', dashboard_stats, name='dashboard_stats'),
    path('users/', user_list_create, name='user-list-create'),
    path('users/<int:pk>/', user_detail, name='user-detail'),
    path('photos/', photo_list, name='photo-list'),
    path('photos/<int:pk>/', photo_detail, name='photo-detail'),
    path('current_user/', current_user, name='current_user'),
    path('update_info/', update_info_view, name='update-info'),
    path('update_password/', update_password_view, name='update-password'),
    path('contact/', contact_view, name='contact'),
    path('my_photos/', my_photos_view, name='my-photos'),

    # CSRF token endpoint for AJAX requests
    path('csrf/', get_csrf_token, name='csrf'),
]
