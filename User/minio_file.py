from minio import Minio
from PIL import Image
from io import BytesIO
import os


minio_client = Minio(endpoint=os.getenv("MINIO_ENDPOINT"),
                     access_key=os.getenv("MINIO_ACCESS_KEY"),
                     secret_key=os.getenv("MINIO_SECRET_KEY"),
                     secure=False
                     )


def resize_image(image_path: str, max_size=512):
    """Изменяет размер изображения и возвращает его в байтовом потоке."""
    with Image.open(image_path) as img:
        width, height = img.size
        aspect_ratio = width / height
        
        if width > height:
            new_width = max_size
            new_height = int(new_width / aspect_ratio)
        else:
            new_height = max_size
            new_width = int(new_height * aspect_ratio)
        img = img.resize((new_width, new_height), Image.LANCZOS)
        
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format="PNG")
        img_byte_arr.seek(0)  
        return img_byte_arr


def upload_photo_minio(name, surname, iin):
    file = "photos/2024-12-18T14:06:53.092810.png"
    b_name = "employees"

    if not minio_client.bucket_exists(bucket_name=b_name):
        try:
            minio_client.make_bucket(b_name)
            print("Создали бакет")
        except Exception as e:
            print(f"Ошибка при создании бакета: {e}")

    img_byte_arr = resize_image(file)
    obj_name = f"{name}-{surname}-{iin}.png"
    try:
        minio_client.put_object(b_name, obj_name, img_byte_arr, len(img_byte_arr.getvalue()))
    except Exception:
        raise

    return f"http://localhost:9000/{b_name}/{obj_name}"