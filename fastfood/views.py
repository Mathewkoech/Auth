from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from fastfood.serializers import FoodSerializer
from .models import Food
from django.http.response import JsonResponse
from rest_framework.parsers import JSONParser 
from rest_framework import status
# Create your views here.

@api_view(['GET'])
def getFood(request):
    food = Food.objects.all()
    serializer = FoodSerializer(food, many = True)
    return Response(serializer.data)

@api_view(['POST'])
def postFood(request):
    serializer = FoodSerializer(data = request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)