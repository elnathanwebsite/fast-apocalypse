import pygame
import sys

# 1. Inisialisasi Pygame
pygame.init()

# Konfigurasi Layar
SCREEN_WIDTH = 640
SCREEN_HEIGHT = 480
screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
pygame.display.set_caption("Game Pixel Art Saya")

# Warna
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)

# 2. Muat Aset PNG
# Pastikan file png ada di folder yang sama
player_img = pygame.image.load('player.png')
player_rect = player_img.get_rect()
player_rect.topleft = (300, 200) # Posisi awal

# Kecepatan Player
player_speed = 5

# 3. Game Loop
clock = pygame.time.Clock()
running = True
while running:
    # --- Input Handling ---
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

    keys = pygame.key.get_pressed()
    if keys[pygame.K_LEFT]:
        player_rect.x -= player_speed
    if keys[pygame.K_RIGHT]:
        player_rect.x += player_speed
    if keys[pygame.K_UP]:
        player_rect.y -= player_speed
    if keys[pygame.K_DOWN]:
        player_rect.y += player_speed

    # --- Update Posisi ---
    # Batasan layar
    if player_rect.left < 0: player_rect.left = 0
    if player_rect.right > SCREEN_WIDTH: player_rect.right = SCREEN_WIDTH
    if player_rect.top < 0: player_rect.top = 0
    if player_rect.bottom > SCREEN_HEIGHT: player_rect.bottom = SCREEN_HEIGHT

    # --- Drawing ---
    screen.fill(BLACK) # Latar belakang hitam
    screen.blit(player_img, player_rect) # Gambar player

    pygame.display.flip() # Update layar
    clock.tick(60) # 60 FPS

pygame.quit()
sys.exit()
