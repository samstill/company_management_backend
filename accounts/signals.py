from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser

@receiver(post_save, sender=CustomUser)
def send_verification_email(sender, instance, created, **kwargs):
    if created:
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(instance)
        uid = instance.pk
        verification_link = reverse('accounts:verify-email', kwargs={'uidb64': uid, 'token': token})
        verification_url = f"{settings.SITE_URL}{verification_link}"

        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {verification_url}',
            settings.DEFAULT_FROM_EMAIL,
            [instance.email],
        )
