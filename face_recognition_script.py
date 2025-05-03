import os
import time

import cv2

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
image_dir = "known_faces"
image_extensions = ['.jpg', '.jpeg', '.png', '.webp']
known_faces = []
known_face_names = []


def load_known_faces():
    global known_faces, known_face_names
    directory_names = os.listdir(image_dir)
    for directory_name in directory_names:
        dir_path = os.path.join(image_dir, directory_name)
        if not os.path.isdir(dir_path):
            continue

        for filename in os.listdir(dir_path):
            if any(filename.lower().endswith(ext) for ext in image_extensions):
                image_path = os.path.join(dir_path, filename)
                image = cv2.imread(image_path)

                if image is None:
                    print(f"❌ Не вдалося завантажити {image_path}. Перевір шлях до файлу.")
                    continue

                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=3, minSize=(30, 30))

                if len(faces) == 0:
                    print(f"❌ Не знайдено обличчя на зображенні {filename}.")
                    continue

                for (x, y, w, h) in faces:
                    face = gray[y:y + h, x:x + w]
                    face = cv2.resize(face, (100, 100))
                    known_faces.append(face)
                    known_face_names.append(directory_name)

    if len(known_faces) == 0:
        print("❌ Не знайдено жодного обличчя в усіх зображеннях.")
        exit()


def recognize_faces_in_video():
    video = cv2.VideoCapture(0)
    if not video.isOpened():
        print("❌ Не вдалося відкрити камеру.")
        return False

    print("✅ Камера запущена. Натисни 'q' для виходу.")
    start_time = time.time()
    while True:
        ret, frame = video.read()
        if not ret:
            print("⚠️ Не вдалося зчитати кадр з камери.")
            break

        if frame is None:
            print("⚠️ Кадр з камери порожній.")
            break

        cv2.imshow("Video", frame)
        if time.time() - start_time > 5:
            break

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    while True:
        ret, frame = video.read()
        if not ret:
            print("⚠️ Не вдалося зчитати кадр з камери.")
            break

        if frame is None:
            print("⚠️ Кадр з камери порожній.")
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)

        for (x, y, w, h) in faces:
            face = gray[y:y + h, x:x + w]
            face = cv2.resize(face, (100, 100))
            min_score = float('inf')
            best_match = "Unknown"

            for i, known_face in enumerate(known_faces):
                diff = cv2.absdiff(known_face, face)
                score = diff.mean()

                if score < min_score:
                    min_score = score
                    if score < 50:
                        best_match = known_face_names[i]

            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
            cv2.putText(frame, best_match, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 0), 2)

            if best_match != "Unknown" and min_score < 50:
                print(f"✅ Знайдено: {best_match}")
                video.release()
                time.sleep(5)
                cv2.destroyAllWindows()
                return True
            if best_match == "Unknown":
                return False
        time.sleep(5)
        cv2.imshow("Video", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    video.release()
    cv2.destroyAllWindows()

    return False

def main():
    load_known_faces()
    if recognize_faces_in_video():
        print("✅ Обличчя знайдено та розпізнано.")
        return True
    else:
        print("❌ Обличчя не знайдено або не розпізнано.")
        return False
