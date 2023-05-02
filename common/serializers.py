from rest_framework import serializers

class BaseModelSerializer(serializers.ModelSerializer):
    """
   Base Serializer class that implements shared functionality
   across all ModelSerializers
    """
    
    class Meta:
        read_only_fields = ("id", "company", "is_deleted", "deleted_at", "modified_by")
        exclude = ("deleted_at",)


class BaseModelSerializerWithoutCommon(serializers.ModelSerializer):
    """
   Base Serializer class that implements shared functionality
   across all ModelSerializers
    """
    
    class Meta:
        read_only_fields = ("id",)
        fields = '__all__'