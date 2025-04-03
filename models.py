from django.db import models
from django.conf import settings



class Photo(models.Model):
    CATEGORY_CHOICES = [
        ('landscape', 'Landscape'),
        ('portrait', 'Portrait'),
        ('animal', 'Animal'),
    ]
    image = models.ImageField(upload_to='photos/')
    description = models.TextField(blank=True, null=True)  # May be unused in upload
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='landscape')
    order = models.IntegerField(default=0)  # To control display order
    show_in_public = models.BooleanField(default=True)  # Controls public visibility
    created_at = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='photos'
    )

    def __str__(self):
        return f"Photo {self.id} ({self.category}) uploaded by {self.owner.username}"
    
class PageView(models.Model):
    page = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)

    def __str__(self):
        return f"{self.page} viewed at {self.timestamp}"