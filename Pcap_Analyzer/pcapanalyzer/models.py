from django.db import models

class Control(models.Model):
    creation_date = models.DateTimeField(20)
    file = models.TextField(100)
    protocol = models.TextField(40)
    status = models.TextField()

def __unicode__(self):
    return Control.status