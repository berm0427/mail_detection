import pickle
import json
from pprint import pprint
import pandas as pd
import numpy as np

def show_actual_training_content(obj, max_samples=10, max_text_length=200):
    """실제 학습 데이터 내용을 자세히 표시"""
    
    print("\n" + "="*80)
    print("📖 ACTUAL TRAINING DATA CONTENT")
    print("="*80)
    
    def display_data_samples(data, label, max_samples=max_samples):
        print(f"\n🎯 {label}:")
        print("-" * 50)
        
        if isinstance(data, np.ndarray):
            print(f"📐 Shape: {data.shape}")
            print(f"🔢 Data type: {data.dtype}")
            
            # 1차원 배열 (라벨 등)
            if len(data.shape) == 1:
                print(f"📊 Sample values ({min(max_samples, len(data))} out of {len(data)}):")
                for i in range(min(max_samples, len(data))):
                    print(f"   [{i:3d}]: {data[i]}")
                    
            # 2차원 배열 (특성 벡터 등)
            elif len(data.shape) == 2:
                print(f"📊 Sample rows ({min(max_samples, len(data))} out of {len(data)}):")
                for i in range(min(max_samples, len(data))):
                    row_str = str(data[i][:10].tolist())  # 처음 10개 특성만
                    if data.shape[1] > 10:
                        row_str = row_str[:-1] + ", ...]"
                    print(f"   Row [{i:3d}]: {row_str}")
                    
        elif isinstance(data, (list, tuple)):
            print(f"📏 Length: {len(data)}")
            print(f"📊 Sample items ({min(max_samples, len(data))} out of {len(data)}):")
            
            for i in range(min(max_samples, len(data))):
                item = data[i]
                if isinstance(item, str):
                    # 텍스트 데이터인 경우 - 이메일 내용 등
                    display_text = item[:max_text_length]
                    if len(item) > max_text_length:
                        display_text += "..."
                    print(f"   [{i:3d}]: \"{display_text}\"")
                else:
                    print(f"   [{i:3d}]: {item}")
                    
        elif isinstance(data, pd.DataFrame):
            print(f"📐 Shape: {data.shape}")
            print(f"📋 Columns: {data.columns.tolist()}")
            print(f"📊 Sample data:")
            print(data.head(max_samples).to_string(max_cols=6, max_colwidth=50))
    
    # 딕셔너리에서 학습 데이터 찾기
    if isinstance(obj, dict):
        # 일반적인 학습 데이터 키들
        data_keys = ['X_train', 'y_train', 'X_test', 'y_test', 'X', 'y', 
                    'training_data', 'train_data', 'emails', 'texts', 'labels',
                    'features', 'targets', 'data', 'dataset']
        
        found_data = False
        for key in obj.keys():
            # 키 이름으로 학습 데이터 찾기
            if any(data_key.lower() in key.lower() for data_key in data_keys):
                display_data_samples(obj[key], f"Data from key '{key}'")
                found_data = True
        
        # 데이터가 없으면 모든 배열/리스트 타입 표시
        if not found_data:
            print("\n⚠️  No obvious training data keys found. Showing all array/list data:")
            for key, value in obj.items():
                if isinstance(value, (np.ndarray, list, tuple, pd.DataFrame)):
                    display_data_samples(value, f"Data from key '{key}'")
    
    # 리스트나 배열인 경우
    elif isinstance(obj, (list, tuple, np.ndarray)):
        display_data_samples(obj, "Root data structure")

def extract_text_content(obj, max_samples=15):
    """텍스트 내용을 추출하여 표시 (이메일, 텍스트 등)"""
    
    print("\n" + "="*80)
    print("📝 TEXT CONTENT EXTRACTION")
    print("="*80)
    
    def find_and_display_text(data, path=""):
        text_found = False
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if find_and_display_text(value, current_path):
                    text_found = True
                    
        elif isinstance(data, (list, tuple)):
            if len(data) > 0 and isinstance(data[0], str):
                print(f"\n🔤 Text data found at: {path}")
                print(f"📏 Count: {len(data)} items")
                print("📄 Sample texts:")
                print("-" * 60)
                
                for i, text in enumerate(data[:max_samples]):
                    # 이메일 헤더나 HTML 태그 간단히 정리
                    clean_text = str(text).replace('\n', ' ').replace('\r', '')
                    if len(clean_text) > 300:
                        clean_text = clean_text[:300] + "..."
                        
                    print(f"\n[{i+1:2d}] {clean_text}")
                    
                if len(data) > max_samples:
                    print(f"\n... and {len(data) - max_samples} more text items")
                text_found = True
                
        elif isinstance(data, np.ndarray) and data.dtype.kind in ['U', 'S', 'O']:  # 문자열 타입
            print(f"\n🔤 Text array found at: {path}")
            print(f"📐 Shape: {data.shape}")
            print("📄 Sample texts:")
            print("-" * 60)
            
            for i in range(min(max_samples, len(data))):
                text = str(data[i])
                if len(text) > 300:
                    text = text[:300] + "..."
                print(f"\n[{i+1:2d}] {text}")
                
            text_found = True
            
        return text_found
    
    if not find_and_display_text(obj):
        print("❌ No text content found in the data structure.")

def comprehensive_data_viewer(file_path, max_samples=10, show_text=True):
    """포괄적인 데이터 내용 뷰어"""
    
    print("="*80)
    print(f"🔍 COMPREHENSIVE DATA CONTENT VIEWER")
    print(f"📁 File: {file_path}")
    print("="*80)
    
    try:
        with open(file_path, 'rb') as f:
            loaded_object = pickle.load(f)
        
        print(f"✅ File loaded successfully!")
        print(f"📊 Root type: {type(loaded_object).__name__}")
        
        # 1. 기본 구조 정보
        if isinstance(loaded_object, dict):
            print(f"📚 Dictionary with {len(loaded_object)} keys:")
            for key, value in loaded_object.items():
                print(f"   🔑 '{key}': {type(value).__name__}", end="")
                if hasattr(value, 'shape'):
                    print(f" - Shape: {value.shape}")
                elif hasattr(value, '__len__'):
                    try:
                        print(f" - Length: {len(value)}")
                    except:
                        print("")
                else:
                    print("")
        
        # 2. 실제 학습 데이터 내용 표시
        show_actual_training_content(loaded_object, max_samples)
        
        # 3. 텍스트 내용 추출 (이메일 등)
        if show_text:
            extract_text_content(loaded_object, max_samples)
        
        # 4. 통계 정보
        print("\n" + "="*80)
        print("📈 DATA STATISTICS")
        print("="*80)
        
        def show_statistics(data, label):
            print(f"\n📊 {label}:")
            if isinstance(data, np.ndarray):
                if data.dtype.kind in ['i', 'f']:  # 숫자 데이터
                    print(f"   Min: {np.min(data):.4f}")
                    print(f"   Max: {np.max(data):.4f}")
                    print(f"   Mean: {np.mean(data):.4f}")
                    print(f"   Std: {np.std(data):.4f}")
                elif data.dtype.kind in ['U', 'S', 'O']:  # 문자열 데이터
                    unique_count = len(np.unique(data)) if data.size < 10000 else "Large dataset"
                    print(f"   Unique values: {unique_count}")
                    print(f"   Sample unique values: {np.unique(data)[:5].tolist()}")
        
        if isinstance(loaded_object, dict):
            for key, value in loaded_object.items():
                if isinstance(value, np.ndarray):
                    show_statistics(value, f"'{key}'")
        
        print("\n" + "="*80)
        print("✨ Comprehensive analysis complete!")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

# 사용법
if __name__ == "__main__":
    # 파일 경로를 실제 PKL 파일로 변경하세요
    file_path = 'phishing_knowledge_base.pkl'
    
    print("🎯 Select viewing option:")
    print("1. Show sample data (10 samples)")
    print("2. Show more data (25 samples)")
    print("3. Show extensive data (50 samples)")
    print("4. Custom sample count")
    
    choice = input("Enter choice (1-4, default=1): ").strip() or "1"
    
    if choice == "1":
        comprehensive_data_viewer(file_path, max_samples=10)
    elif choice == "2":
        comprehensive_data_viewer(file_path, max_samples=25)
    elif choice == "3":
        comprehensive_data_viewer(file_path, max_samples=50)
    elif choice == "4":
        try:
            samples = int(input("Enter number of samples to show: "))
            comprehensive_data_viewer(file_path, max_samples=samples)
        except:
            comprehensive_data_viewer(file_path, max_samples=10)
    else:
        comprehensive_data_viewer(file_path, max_samples=10)