from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Load pretrained multilingual MiniLM
model = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

# 2. Example dataset (texts + labels)
texts = [
    "Update your password now to avoid account suspension",  # phishing (English)
    "Ваш аккаунт будет заблокирован, если вы не подтвердите", # phishing (Russian)
    "कृपया अपनी बैंक जानकारी साझा करें",                       # phishing (Hindi)
    "你好，请提供你的银行卡号以验证账户",                        # phishing (Chinese)
    "Hello, here is the meeting agenda for tomorrow",        # safe
    "This is your flight itinerary for next week",           # safe
    "Здесь ваши билеты на поезд",                           # safe (Russian)
    "कक्षा कल सुबह 10 बजे शुरू होगी",                          # safe (Hindi)
    "明天的课程安排已更新",                                      # safe (Chinese)
]
labels = [1, 1, 1, 1, 0, 0, 0, 0, 0]  # 1 = phishing, 0 = safe

# 3. Encode texts into embeddings
X = model.encode(texts)

# 4. Train a simple classifier
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.3, random_state=42)
clf = LogisticRegression(max_iter=200)
clf.fit(X_train, y_train)

# 5. Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# 6. Test on new samples
new_samples = [
    "Click here to claim your free reward",    # phishing
    "这是你的课堂笔记",                          # safe (Chinese: "This is your class notes")
]

new_embeddings = model.encode(new_samples)
predictions = clf.predict(new_embeddings)
for text, pred in zip(new_samples, predictions):
    print(f"{text} --> {'Phishing' if pred==1 else 'Safe'}")
