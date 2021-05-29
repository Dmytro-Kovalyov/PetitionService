from django.contrib.auth.models import User
from django.db import models
from django.conf import settings
import datetime
from django.utils import timezone

class Category(models.Model):
    name = models.CharField('Category', max_length=200)
    description = models.TextField('Text')

class Petition(models.Model):
    title = models.CharField('Petition', max_length=200)
    description = models.CharField('Petition', max_length=1000)
    text = models.TextField('Text')
    datetime_created = models.DateTimeField('Datetime created', auto_now_add=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='creator')
    voters = models.ManyToManyField(User, related_name='voter')

    def DateExpires(self):
        return self.datetime_created + datetime.timedelta(days=settings.MAX_DAYS)

    def IsExpired(self):
        return timezone.now() > self.DateExpires()

    def VoteCount(self):
        return self.voters.all().count()

    def HasPassed(self):
        return self.VoteCount() >= settings.NEEDED_VOTE_COUNT