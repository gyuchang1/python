import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import pyvisa
import csv
import time
import threading
from datetime import datetime
import matplotlib
matplotlib.use("TkAgg")   # ✅ Qt 백엔드 방지
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os

class PowerSupplyController:
    def __init__(self, root):
        self.root = root
        self.root.title("E36233A Sequence Controller")

        # 창 닫기 이벤트 핸들러 등록
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.rm = pyvisa.ResourceManager()
        self.instrument = None
        self.sequence = []
        self.stop_flag = False
        self.csv_file_path = None
        self.log_file_path = "psu_sequence_log.csv"
        self.sampling_interval = 10  # 기본 10초
        self.remaining_time = 0

        self.create_widgets()
        self.create_graph()

    def create_widgets(self):
        # VISA 검색
        tk.Label(self.root, text="VISA 장비 선택:").grid(row=0, column=0, sticky="w")
        self.visa_list = tk.Listbox(self.root, width=60, height=3)
        self.visa_list.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        tk.Button(self.root, text="장비 검색", command=self.scan_devices).grid(row=1, column=2)

        # CSV 선택
        tk.Label(self.root, text="시퀀스 CSV:").grid(row=2, column=0, sticky="w")
        self.csv_entry = tk.Entry(self.root, width=50)
        self.csv_entry.grid(row=2, column=1)
        tk.Button(self.root, text="파일 선택", command=self.load_csv_file).grid(row=2, column=2)

        # 로그 경로
        tk.Label(self.root, text="로그 저장 경로:").grid(row=3, column=0, sticky="w")
        self.log_entry = tk.Entry(self.root, width=50)
        self.log_entry.insert(0, self.log_file_path)
        self.log_entry.grid(row=3, column=1)
        tk.Button(self.root, text="경로 선택", command=self.select_log_path).grid(row=3, column=2)

        # 샘플링 주기
        tk.Label(self.root, text="샘플링 간격(초):").grid(row=4, column=0, sticky="w")
        self.sampling_spin = tk.Spinbox(self.root, from_=1, to=3600, width=8, command=self.update_sampling_interval)
        self.sampling_spin.delete(0, tk.END)
        self.sampling_spin.insert(0, str(self.sampling_interval))
        self.sampling_spin.grid(row=4, column=1, sticky="w")

        # 남은 시간 표시
        tk.Label(self.root, text="남은 시간:").grid(row=4, column=2, sticky="e")
        self.remaining_label = tk.Label(self.root, text="00:00:00", width=10)
        self.remaining_label.grid(row=4, column=3, sticky="w")

        # Treeview
        self.tree = ttk.Treeview(self.root, columns=("CH1", "CH1_I", "CH2", "CH2_I", "Duration"), show="headings", height=6)
        self.tree.heading("CH1", text="CH1 Voltage (V)")
        self.tree.heading("CH1_I", text="CH1 Current (A)")
        self.tree.heading("CH2", text="CH2 Voltage (V)")
        self.tree.heading("CH2_I", text="CH2 Current (A)")
        self.tree.heading("Duration", text="Duration (s)")
        self.tree.grid(row=5, column=0, columnspan=4, padx=5, pady=5)
        self.tree.bind('<Double-1>', self.edit_cell)

        # CSV 저장
        tk.Button(self.root, text="CSV 저장", command=self.save_csv_file).grid(row=6, column=0, pady=5)
        # 행 삭제 버튼
        #tk.Button(self.root, text="행 삭제", command=self.delete_selected_row).grid(row=6, column=4, pady=5)

        # 실행/중단/Progress
        tk.Button(self.root, text="시작", bg="green", fg="white", command=self.start_sequence_thread).grid(row=6, column=1)
        tk.Button(self.root, text="중단", bg="red", fg="white", command=self.stop_sequence).grid(row=6, column=2)
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=6, column=3, pady=5)

        # 로그창
        self.log_text = tk.Text(self.root, width=90, height=8)
        self.log_text.grid(row=7, column=0, columnspan=4, padx=5, pady=5)
        self.ensure_sequence_csv()
        
    def ensure_sequence_csv(self):
    # 기본 시퀀스 파일 경로 (프로그램 폴더 기준)
        default_csv = "default_sequence.csv"
        self.csv_file_path = default_csv
        self.csv_entry.delete(0, tk.END)
        self.csv_entry.insert(0, default_csv)

        # 없으면 새로 생성
        if not os.path.exists(default_csv):
            with open(default_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["CH1_Voltage", "CH1_Current", "CH2_Voltage", "CH2_Current", "Duration_sec"])
                # 기본 Step 하나 넣어줌 (예: 5V 0.5A 5V 0.5A 10초)
                writer.writerow([5.0, 0.5, 5.0, 0.5, 10])
            self.log(f"[INFO] 기본 시퀀스 CSV 생성: {default_csv}")

        # 트리뷰 초기화 및 로드
        for i in self.tree.get_children():
            self.tree.delete(i)
        with open(default_csv, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.tree.insert("", tk.END, values=(
                    row["CH1_Voltage"], row["CH1_Current"], 
                    row["CH2_Voltage"], row["CH2_Current"], 
                    row["Duration_sec"]
                ))                          

    def create_graph(self):
        self.fig, self.ax = plt.subplots(2, 1, figsize=(7, 4), sharex=True)
        self.ax[0].set_ylabel("Voltage (V)")
        self.ax[1].set_ylabel("Current (A)")
        self.ax[1].set_xlabel("Samples")
        self.ch1_v_data, self.ch2_v_data = [], []
        self.ch1_i_data, self.ch2_i_data = [], []
        self.samples = []

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().grid(row=8, column=0, columnspan=4)

    def update_sampling_interval(self):
        try:
            self.sampling_interval = int(self.sampling_spin.get())
            self.log(f"[INFO] 샘플링 간격: {self.sampling_interval}초")
        except ValueError:
            self.log("[ERROR] 올바른 숫자를 입력하세요.")

    def update_remaining_time(self):
        hrs, rem = divmod(self.remaining_time, 3600)
        mins, secs = divmod(rem, 60)
        self.remaining_label.config(text=f"{hrs:02}:{mins:02}:{secs:02}")

    def update_graph(self):
        self.ax[0].clear()
        self.ax[1].clear()
        self.ax[0].plot(self.samples, self.ch1_v_data, label="CH1 V")
        self.ax[0].plot(self.samples, self.ch2_v_data, label="CH2 V")
        self.ax[1].plot(self.samples, self.ch1_i_data, label="CH1 I")
        self.ax[1].plot(self.samples, self.ch2_i_data, label="CH2 I")
        self.ax[0].legend()
        self.ax[1].legend()
        self.ax[0].set_ylabel("Voltage (V)")
        self.ax[1].set_ylabel("Current (A)")
        self.ax[1].set_xlabel("Samples")
        self.canvas.draw_idle()

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def scan_devices(self):
        self.visa_list.delete(0, tk.END)
        try:
            resources = self.rm.list_resources()
            for res in resources:
                self.visa_list.insert(tk.END, res)
            self.log(f"[INFO] {len(resources)}개 장비 검색됨")
        except Exception as e:
            self.log(f"[ERROR] 장비 검색 실패: {e}")

    def load_csv_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV 파일", "*.csv")])
        if filepath:
            self.csv_file_path = filepath
            self.csv_entry.delete(0, tk.END)
            self.csv_entry.insert(0, filepath)
            self.log(f"[INFO] CSV 파일 선택: {filepath}")
            for i in self.tree.get_children():
                self.tree.delete(i)
            with open(filepath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.tree.insert("", tk.END, values=(row["CH1_Voltage"], row["CH1_Current"], row["CH2_Voltage"], row["CH2_Current"], row["Duration_sec"]))

    def select_log_path(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV 파일", "*.csv")])
        if filepath:
            self.log_file_path = filepath
            self.log_entry.delete(0, tk.END)
            self.log_entry.insert(0, filepath)
            self.log(f"[INFO] 로그 경로 설정: {filepath}")

    def edit_cell(self, event):
        item = self.tree.selection()[0]
        col = self.tree.identify_column(event.x)
        col_index = int(col.replace('#', '')) - 1
        old_value = self.tree.item(item, "values")[col_index]
        new_value = simpledialog.askstring("값 수정", f"새 값 입력 (현재: {old_value})")
        if new_value:
            values = list(self.tree.item(item, "values"))
            values[col_index] = new_value
            self.tree.item(item, values=values)

    def save_csv_file(self):
        if not self.csv_file_path:
            messagebox.showerror("에러", "CSV 파일을 먼저 불러오세요.")
            return
        with open(self.csv_file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["CH1_Voltage", "CH1_Current", "CH2_Voltage", "CH2_Current", "Duration_sec"])
            for row_id in self.tree.get_children():
                vals = self.tree.item(row_id)["values"]
                writer.writerow(vals)   # ✅ 모든 행 저장
        self.log(f"[INFO] CSV 저장 완료: {self.csv_file_path}")

    def delete_selected_row(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("경고", "삭제할 행을 선택하세요.")
            return
        for item in selected:
            self.tree.delete(item)
        self.log("[INFO] 선택한 행 삭제됨")

    def stop_sequence(self):
        self.stop_flag = True
        self.log("[INFO] 시퀀스 중단 요청")

    def start_sequence_thread(self):
        t = threading.Thread(target=self.run_sequence)
        t.daemon = True
        t.start()

    def run_sequence(self):
        try:
            selected = self.visa_list.curselection()
            if not selected:
                self.root.after(0, lambda: messagebox.showerror("에러", "장비를 선택하세요."))
                return
            visa_address = self.visa_list.get(selected[0])
            self.log_file_path = self.log_entry.get()
            self.sequence = []
            for row_id in self.tree.get_children():
                vals = self.tree.item(row_id)["values"]
                self.sequence.append({"ch1_v": float(vals[0]), "ch1_i": float(vals[1]), "ch2_v": float(vals[2]), "ch2_i": float(vals[3]), "duration": int(vals[4])})

            self.instrument = self.rm.open_resource(visa_address)
            self.instrument.write("*RST")

            # ✅ 명령 분리: 채널 선택 후 OUTP ON
            self.instrument.write("INST:NSEL 1")
            self.instrument.write("OUTP ON")
            self.instrument.write("INST:NSEL 2")
            self.instrument.write("OUTP ON")

            # 로그 파일 준비
            file_exists = os.path.exists(self.log_file_path)
            with open(self.log_file_path, "a", newline="") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["Timestamp", "CH1 Set V", "CH1 Measured V", "CH1 Measured I",
                                     "CH2 Set V", "CH2 Measured V", "CH2 Measured I"])

            self.root.after(0, lambda: self.progress.config(maximum=len(self.sequence)))
            self.stop_flag = False
            self.samples.clear()
            self.ch1_v_data.clear()
            self.ch2_v_data.clear()
            self.ch1_i_data.clear()
            self.ch2_i_data.clear()

            for idx, step in enumerate(self.sequence):
                if self.stop_flag: break
                ch1_voltage = step["ch1_v"]
                ch1_current = step["ch1_i"]
                ch2_voltage = step["ch2_v"]
                ch2_current = step["ch2_i"]
                duration = step["duration"]
                self.remaining_time = duration
                self.root.after(0, self.update_remaining_time)

                # ✅ 전압/전류 설정
                self.instrument.write("INST:NSEL 1")
                self.instrument.write(f"VOLT {ch1_voltage}")
                self.instrument.write(f"CURR {ch1_current}")
                self.instrument.write("INST:NSEL 2")
                self.instrument.write(f"VOLT {ch2_voltage}")
                self.instrument.write(f"CURR {ch2_current}")

                self.root.after(0, lambda msg=f"[Step {idx+1}] CH1={ch1_voltage}V, CH2={ch2_voltage}V 유지 {duration}s": self.log(msg))
                self.root.after(0, lambda val=idx+1: self.progress.config(value=val))

                start_time = time.time()
                while time.time() - start_time < duration:
                    if self.stop_flag: break
                    self.remaining_time = duration - int(time.time() - start_time)
                    self.root.after(0, self.update_remaining_time)

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.instrument.write("INST:NSEL 1")
                    ch1_meas_v = float(self.instrument.query("MEAS:VOLT?"))
                    ch1_meas_i = float(self.instrument.query("MEAS:CURR?"))
                    self.instrument.write("INST:NSEL 2")
                    ch2_meas_v = float(self.instrument.query("MEAS:VOLT?"))
                    ch2_meas_i = float(self.instrument.query("MEAS:CURR?"))

                    with open(self.log_file_path, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([timestamp, ch1_voltage, ch1_meas_v, ch1_meas_i,
                                         ch2_voltage, ch2_meas_v, ch2_meas_i])

                    self.samples.append(len(self.samples))
                    self.ch1_v_data.append(ch1_meas_v)
                    self.ch2_v_data.append(ch2_meas_v)
                    self.ch1_i_data.append(ch1_meas_i)
                    self.ch2_i_data.append(ch2_meas_i)

                    self.root.after(0, self.update_graph)
                    self.root.after(0, lambda msg=f"[{timestamp}] CH1: {ch1_meas_v:.2f}V {ch1_meas_i:.3f}A | CH2: {ch2_meas_v:.2f}V {ch2_meas_i:.3f}A": self.log(msg))

                    time.sleep(self.sampling_interval)

            self.instrument.write("INST:NSEL 1")
            self.instrument.write("OUTP OFF")
            self.instrument.write("INST:NSEL 2")
            self.instrument.write("OUTP OFF")
            self.instrument.close()
            self.root.after(0, lambda: self.log(f"[INFO] 시퀀스 완료. 로그: {self.log_file_path}"))
            self.root.after(0, lambda: self.remaining_label.config(text="완료"))

        except Exception as e:
            self.root.after(0, lambda msg=f"[ERROR] 실행 중 오류: {e}": self.log(msg))

    def on_close(self):
        """창 닫기 이벤트"""
        self.stop_flag = True
        if self.instrument:
            try:
                self.instrument.close()
            except:
                pass
        self.root.destroy()
        os._exit(0)
# 실행
if __name__ == "__main__":
    root = tk.Tk()
    app = PowerSupplyController(root)
    root.mainloop()
