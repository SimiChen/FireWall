from django.db import models


# Create your models here.


class PacketBaseInfo(models.Model):
    timestamp = models.DateTimeField()
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    src_port = models.CharField(max_length=100)
    dst_port = models.CharField(max_length=100)
    method = models.CharField(max_length=100)
    protocol = models.CharField(max_length=50)
    path = models.TextField()
    hostname = models.CharField(max_length=100)
    user_agent = models.TextField()
    referer = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"Packet {self.id}"


class PacketAttackDetails(models.Model):
    base_info = models.ForeignKey(PacketBaseInfo, on_delete=models.CASCADE)     # 关联上面的表，方便调用
    attack = models.CharField(max_length=100)
    feature = models.TextField()
    threat = models.CharField(max_length=100)

    def __str__(self):
        return f"Packet {self.id}"
