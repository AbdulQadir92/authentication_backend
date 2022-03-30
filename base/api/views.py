from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import *
from base.models import Note

from django.contrib.auth.models import User, auth
from django.http import JsonResponse


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        return token


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


@api_view(['GET'])
def getRoutes(request):
    routes = [
        '/api/token',
        '/api/token/refresh'
    ]
    return Response(routes)

@api_view(['POST'])
def registerUser(request):
    data = request.data
    username = data['username']
    email = data['email']
    password1 = data['password1']
    password2 = data['password2']

    if password1 == password2:
        if User.objects.filter(username=username).exists():
            return JsonResponse({'message': 'Username already exists'})
        elif User.objects.filter(email=email).exists():
            return JsonResponse({'message': 'User with this email already exists'})    
        else:
            user = User.objects.create_user(username=username, password=password1, email=email)
            _user = auth.authenticate(username=username, password=password1)
            if _user is not None:
                auth.login(request, _user)
            else:
                return JsonResponse({'message': 'User was not created'})

            return JsonResponse({'message': 'User created successfully'})
    else:
        return JsonResponse({'message': 'Passwords do not match'})

    return JsonResponse({'message': 'Register'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getNotes(request):
    user = request.user
    notes = user.note_set.all()
    serializer = NoteSerializer(notes, many=True)
    return Response(serializer.data)