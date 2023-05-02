
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from fastfood_auth.views import(ContentTypeListView,
    RegisterNonAdminUSerView,
    UsersListView,
    UserDetailView,)


urlpatterns = [
path("users/", UsersListView.as_view(), name="users"),
path("users/<uuid:pk>/", UserDetailView.as_view(), name="user_details"),
path("users/details/", UserDetailView.as_view(), name="own_details"),
]