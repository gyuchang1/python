import sys
import numpy as np
import cv2
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QLabel, QFileDialog, QGridLayout
)
from colour import RGB_to_XYZ, XYZ_to_xy, CCS_ILLUMINANTS, RGB_COLOURSPACES
from colour.plotting import plot_RGB_chromaticities_in_chromaticity_diagram_CIE1931
import matplotlib.pyplot as plt

class RGBChartUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RGB Average & Chromaticity Viewer")
        self.setGeometry(100, 100, 400, 300)

        self.rgb_values = []
        self.labels = [QLabel("Image {}: Not Loaded".format(i+1)) for i in range(4)]

        layout = QVBoxLayout()
        grid = QGridLayout()
        for i, label in enumerate(self.labels):
            grid.addWidget(label, i, 0)
            btn = QPushButton(f"Load Image {i+1}")
            btn.clicked.connect(lambda _, idx=i: self.load_image(idx))
            grid.addWidget(btn, i, 1)
        layout.addLayout(grid)

        self.calc_btn = QPushButton("Calculate & Show Chromaticity")
        self.calc_btn.clicked.connect(self.calculate_rgb)
        layout.addWidget(self.calc_btn)

        self.setLayout(layout)

    def load_image(self, index):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Image")
        if file_name:
            image = cv2.imread(file_name)
            if image is None:
                self.labels[index].setText("Failed to Load Image")
                return
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            avg_rgb = np.mean(rgb.reshape(-1, 3), axis=0).tolist()
            if len(self.rgb_values) > index:
                self.rgb_values[index] = avg_rgb
            else:
                self.rgb_values.append(avg_rgb)
            self.labels[index].setText(f"Image {index+1} Avg RGB: {np.round(avg_rgb, 2)}")

    def calculate_rgb(self):
        if len(self.rgb_values) != 4:
            print("Load 4 images first.")
            return

        D65 = CCS_ILLUMINANTS['CIE 1931 2 Degree Standard Observer']['D65']
        RGB2XYZ_mat = RGB_COLOURSPACES['sRGB'].matrix_RGB_to_XYZ
        RGB_data_VL_chart_50 = self.rgb_values

        # 변환
        XYZ = RGB_to_XYZ(RGB_data_VL_chart_50, D65, D65, RGB2XYZ_mat)
        xy = XYZ_to_xy(XYZ)

        print("RGB Data:", RGB_data_VL_chart_50)
        print("Chromaticity (xy):", xy)

        # 시각화
        plt.figure()
        plot_RGB_chromaticities_in_chromaticity_diagram_CIE1931(
            RGB_data_VL_chart_50,
            scatter_kwargs={'s': 50, 'c': 'black', 'marker': 'x', 'alpha': 1}
        )
        plt.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RGBChartUI()
    window.show()
    sys.exit(app.exec_())
