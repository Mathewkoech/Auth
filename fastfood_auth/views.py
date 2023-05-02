from django.shortcuts import render
from rest_framework.views import APIView
from fastfood_auth.models import User
from django.contrib.contenttypes.models import ContentType
from rest_framework.decorators import api_view, permission_classes
from allauth.account.models import EmailAddress
import datetime
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from django.contrib.contenttypes.models import ContentType
from fastfood_auth.decorators import permission_required
from dj_rest_auth.registration.views import VerifyEmailView, RegisterView
from common.views import BaseDetailView, BaseListView, GlobalListView
from dj_rest_auth.app_settings import create_token, TokenSerializer
from fastfood_auth.serializers import (
    ContentTypeSerializer,
    GroupSerializer,
    ListUserSerializer,
    PermissionsSerializer,
    ReadGroupSerializer,
    ReadRoleSerializer,
    ReadUserSerializer,
    RegisterNonAdminUserSerializer,
    RoleSerializer,
    UserSerializer,
)


@api_view()
def null_view(request):
    return Response(status=status.HTTP_400_BAD_REQUEST)


class CustomVerifyEmailView(VerifyEmailView):
    """
    Overrides the post method of the default VerifyEmailView.
    Returns a JWT token for the user to login with after verification.
    """

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs["key"] = serializer.validated_data["key"]
        confirmation = self.get_object()
        confirmation.confirm(request)
        user = confirmation.email_address.user
        token = get_jwt(user)
        return Response(token, status=status.HTTP_200_OK)


class RegisterNonAdminUSerView(RegisterView):
    serializer_class = RegisterNonAdminUserSerializer
    permission_classes = (IsAuthenticated,)


class TokenBasedLoginView(LoginView):
    """
    A custom login view for users that require token based login
    """

    def login(self):
        self.user = self.serializer.validated_data["user"]
        self.token = create_token(self.token_model, self.user, self.serializer)

    def get_response(self):
        serializer = TokenSerializer(
            instance=self.token, context={"request": self.request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class UsersListView(GenericAPIView):
    """
    Users list view
    """

    model = User
    serializer_class = ReadUserSerializer
    read_serializer_class = ReadUserSerializer
    # read_serializer_class = ListUserSerializer

    def get_read_serializer_class(self):
        if self.read_serializer_class is not None:
            return self.read_serializer_class
        return self.serializer_class

    def get_queryset(self):
        if hasattr(self.model, "is_deleted"):
            self.filter_object = Q(profile__company__exact=self.request.user.profile.company) & Q(is_deleted = False)
        else:
            self.filter_object = Q(profile__company__exact=self.request.user.profile.company)
        queryset = self.model.objects.filter(self.filter_object)
        return queryset

    # @method_decorator(cache_page(CACHE_TTL), name='dispatch')
    def get(self, request):
        all_status = request.GET.get("all", None)
        if all_status is not None:
            queryset = self.get_queryset()
            serializer = self.get_read_serializer_class()(queryset, many=True)
            return Response(serializer.data)
        else:
            queryset = self.get_queryset()
            page = self.paginate_queryset(queryset)
            serializer = self.get_read_serializer_class()(page, many=True)
            return self.get_paginated_response(serializer.data)


class UserDetailView(BaseDetailView):
    """
    Update, Delete, or View a User
    """

    model = User
    serializer_class = ReadUserSerializer
    read_serializer_class = ReadUserSerializer

    def get_object(self, request, pk):
        if pk is not None:
            return get_object_or_404(User, pk=pk)
        return request.user

    # @method_decorator(permission_required('serow_auth.view_user', raise_exception=True))
    def get(self, request, pk=None):
        return super().get(request, pk)

    # @method_decorator(permission_required('serow_auth.change_user', raise_exception=True))
    def put(self, request, pk=None):
        return super().put(request, pk)

    @method_decorator(permission_required('serow_auth.delete_user', raise_exception=True))
    def delete(self, request, pk=None):
        item = self.get_object(request, pk)
        if hasattr(item, "is_deleted"):
            item.is_deleted = True
            item.deleted_at = datetime.datetime.now(tz=timezone.utc)
            item.modified_by = request.user
            new_email = str(item.id)+"@deleted.com"
            item.email = new_email
            email_address = EmailAddress.objects.get(user__exact=item.id)
            email_address.email = new_email
            item.is_active = False
            email_address.save()
            item.save()
        else:
            item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_total_users(request):
    total_users = 0
    if request.user.is_company_admin:
        users = User.objects.filter(profile__company=request.user.profile.company,is_active=True)
        for user in users:
            total_users = total_users + 1
        return Response(total_users, status=status.HTTP_200_OK)   
