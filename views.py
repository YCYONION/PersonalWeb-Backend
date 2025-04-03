from datetime import date
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from .serializers import UserSerializer, PhotoSerializer
from .models import Photo, PageView


@ensure_csrf_cookie
@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    return Response({'detail': 'CSRF cookie set'})

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
        return Response({'message': 'Logged in successfully'})
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout_view(request):
    logout(request)
    return Response({'message': 'Logged out successfully'})

@api_view(['GET'])
@permission_classes([AllowAny])
def get_admin_info(request):
    user = request.user
    # This will return empty or default values if no user is logged in.
    # You might want to provide some dummy data for testing.
    if not user or not user.is_authenticated:
        return Response({
            'id': 0,
            'username': 'Guest Admin',
            'first_name': '',
            'last_name': '',
            'email': '',
            'phone': '',
            'description': '',
            'avatar': ''
        })
    return Response({
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'phone': getattr(user, 'phone', ''),
        'description': getattr(user, 'description', ''),
        'avatar': getattr(user, 'avatar', '')
    })

@csrf_exempt
@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsAdminUser])
def update_profile_picture(request):
    user = request.user
    if 'avatar' not in request.FILES:
        return Response({'error': 'No file provided.'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.avatar = request.FILES['avatar']
    user.save()
    # Reload the user instance so that the avatar field is updated to a FieldFile
    user.refresh_from_db()
    
    try:
        avatar_url = user.avatar.url  # Should now be available
    except Exception as e:
        return Response({'error': f'Error retrieving avatar URL: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({'avatar': avatar_url}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def dashboard_stats(request):
    today = timezone.now().date()
    # Count page views for the home page ("/")
    page_views = PageView.objects.filter(page='/', timestamp__date=today).count()
    # Count unique visitors based on distinct session_key for home page
    unique_visitors = PageView.objects.filter(page='/', timestamp__date=today).values('session_key').distinct().count()
    # Count photo views (requests to any URL starting with "/photos/")
    photo_views = PageView.objects.filter(page__startswith='/photos/', timestamp__date=today).count()

    stats = {
        "page_views": page_views,
        "unique_visitors": unique_visitors,
        "photo_views": photo_views,
    }
    return Response(stats)

@api_view(['GET', 'POST'])
def user_list_create(request):
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                password=request.data.get('password'),
                email=serializer.validated_data.get('email', '')
            )
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def user_detail(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = UserSerializer(user)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'DELETE':
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# Public endpoint for viewing photos
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def photo_list(request):
    if request.method == 'GET':
        photos = Photo.objects.all()
        print(photos)
        serializer = PhotoSerializer(photos, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        # Only allow admin to POST
        if not (request.user and request.user.is_staff):
            return Response({'detail': 'Admin credentials required'}, status=status.HTTP_403_FORBIDDEN)
        serializer = PhotoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
@permission_classes([IsAdminUser])
def my_photos_view(request):
    # Return only photos uploaded by the current admin
    photos = Photo.objects.filter(owner=request.user)
    serializer = PhotoSerializer(photos, many=True)
    return Response(serializer.data)
    
@api_view(['GET', 'PUT', 'DELETE'])
def photo_detail(request, pk):
    try:
        photo = Photo.objects.get(pk=pk)
    except Photo.DoesNotExist:
        return Response({'detail': 'Photo not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = PhotoSerializer(photo)
        return Response(serializer.data)
    elif request.method in ['PUT', 'DELETE']:
        # Only allow modifications if the user is an admin.
        if not (request.user and request.user.is_staff):
            return Response({'detail': 'Admin credentials required'}, status=status.HTTP_403_FORBIDDEN)
        if request.method == 'PUT':
            serializer = PhotoSerializer(photo, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # owner remains unchanged
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        elif request.method == 'DELETE':
            photo.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['PUT'])
@permission_classes([IsAdminUser])
def update_info_view(request):
    user = request.user
    data = request.data
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    # Update phone and description; adjust as necessary if using a custom user or profile model.
    user.phone = data.get('phone', getattr(user, 'phone', ''))
    user.description = data.get('description', getattr(user, 'description', ''))
    user.save()
    return Response({
        'id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'phone': getattr(user, 'phone', ''),
        'description': getattr(user, 'description', '')
    }, status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([IsAdminUser])
def update_password_view(request):
    user = request.user
    new_password = request.data.get('new_password')
    if not new_password:
        return Response({'error': 'New password is required.'}, status=status.HTTP_400_BAD_REQUEST)
    user.set_password(new_password)
    user.save()
    return Response({'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def current_user(request):
    if request.user.is_authenticated:
        print(request)
        return Response({
            "id": request.user.id,
            "username": request.user.username,
            "email": request.user.email,
            "is_admin": request.user.is_staff  # or is_superuser, as desired
        })
    else:
        return Response({"detail": "Not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def contact_view(request):
    # Retrieve fields from the request data
    name = request.data.get('name')
    email = request.data.get('email')
    phone = request.data.get('phone')
    details = request.data.get('details')
    
    # Validate required fields (name, email, details)
    if not all([name, email, details]):
        return Response({'error': 'Name, email, and details are required.'},
                        status=status.HTTP_400_BAD_REQUEST)
    
    subject = f'Contact Form Submission from {name}'
    message = (
        f'Name: {name}\n'
        f'Email: {email}\n'
        f'Phone: {phone}\n'
        f'Details:\n{details}'
    )
    recipient_list = ['onion.ycy.photography@gmail.com']
    
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list, fail_silently=False)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({'message': 'Your message has been sent successfully.'}, status=status.HTTP_200_OK)