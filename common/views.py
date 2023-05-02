from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework import status
from rest_framework.response import Response


class BaseListView(GenericAPIView):
    """
        Fetch all instances of a resource or create new resource
    """

    model = None
    filter_object = None
    read_serializer_class = None

    def get_read_serializer_class(self):
        if self.read_serializer_class is not None:
            return self.read_serializer_class
        return self.serializer_class


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

    def post(self, request):
        serializer = self.get_serializer_class()(
            data=request.data, context={"user": request.user}
        )
        if serializer.is_valid():
            company = request.user.profile
            serializer.save(
                created_by=request.user, company=company,
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class GlobalListView(GenericAPIView):
    """
        Fetch all instances of a resource or create new resource
    """

    model = None
    filter_object = None
    read_serializer_class = None

    def get_read_serializer_class(self):
        if self.read_serializer_class is not None:
            return self.read_serializer_class
        return self.serializer_class


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

    def post(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ImageBaseListView(BaseListView):
    """
        Fetch all instances of a resource or create new resource
    """

    def get(self, request):
        all_status = request.GET.get("all", None)
        if all_status is not None:
            queryset = self.get_queryset()
            serializer = self.get_read_serializer_class()(queryset, many=True, context={'request':request})
            return Response(serializer.data)
        else:
            queryset = self.get_queryset()
            page = self.paginate_queryset(queryset)
            serializer = self.get_read_serializer_class()(page, many=True, context={'request':request})
            return self.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = self.get_serializer_class()(
            data=request.data, context={"user": request.user}
        )
        if serializer.is_valid():
            company = request.user.profile.company
            serializer.save(
                created_by=request.user, company=company,
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BaseDetailView(GenericAPIView):
    """
    Update, Delete, or View a resource
    """

    model = None
    filter_object = None
    read_serializer_class = None

    def get_read_serializer_class(self):
        if self.read_serializer_class is not None:
            return self.read_serializer_class
        return self.serializer_class

    def get_queryset(self, request):
        queryset = self.model
        return queryset

    def get_object(self, request, pk):
        queryset = self.get_queryset(request)
        return get_object_or_404(queryset, pk=pk)

    def get(self, request, pk):
        item = self.get_object(request, pk)
        serializer = self.get_read_serializer_class()(item)
        return Response(serializer.data)

    def put(self, request, pk):
        item = self.get_object(request, pk)
        serializer = self.get_serializer_class()(
            item, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save(modified_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        item = self.get_object(request, pk)
        if hasattr(item, "is_deleted"):
            # item.is_deleted = True
            # item.deleted_at = datetime.datetime.now(tz=timezone.utc)
            # item.modified_by = request.user
            # item.save()
            item.delete()
        else:
            item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ImageBaseDetailView(BaseDetailView):
    """
    Update, Delete, or View a resource
    """

    def get(self, request, pk):
        item = self.get_object(request, pk)
        serializer = self.get_read_serializer_class()(
            item, context={'request':request}
        )
        return Response(serializer.data)

    def put(self, request, pk):
        item = self.get_object(request, pk)
        serializer = self.get_serializer_class()(
            item, data=request.data, partial=True, context={'request':request}
        )
        if serializer.is_valid():
            serializer.save(modified_by=request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)