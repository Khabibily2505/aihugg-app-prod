document.addEventListener('DOMContentLoaded', () => {
    // --- CONFIGURAÇÃO CENTRAL ---
    // IMPORTANTE: Coloque aqui o URL do seu backend na Vercel!
    const apiUrl = 'https://aihugg-backend-git-main-edson-fagundes-projects.vercel.app';

    // --- Seletores dos formulários ---
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    
    // --- LÓGICA DE LOGIN ---
    if (loginForm) {
        const messageContainer = document.getElementById('message-container');
        
        // Verifica se veio uma mensagem da página de cadastro
        const urlParams = new URLSearchParams(window.location.search);
        const message = urlParams.get('message');
        if (message) {
            showMessage(decodeURIComponent(message), 'success');
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitButton = loginForm.querySelector('button[type="submit"]');
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            setLoading(submitButton, 'Entrando...', true);

            try {
                const response = await fetch(`${apiUrl}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.erro || 'Credenciais inválidas.');
                }

                // SUCESSO!
                showMessage('Login bem-sucedido! A redirecionar...', 'success');
                localStorage.setItem('aihugg_token', data.access_token); // Guarda o token!
                
                setTimeout(() => {
                    window.location.href = '/dashboard'; // Redireciona para o painel principal
                }, 1500);

            } catch (error) {
                showMessage(error.message, 'error');
                setLoading(submitButton, 'Entrar', false);
            }
        });
    }

    // --- LÓGICA DE CADASTRO ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitButton = registerForm.querySelector('button[type="submit"]');
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            setLoading(submitButton, 'A criar conta...', true);

            try {
                const response = await fetch(`${apiUrl}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.erro || 'Não foi possível criar a conta.');
                }
                
                // SUCESSO! Redireciona para a página de login com uma mensagem
                const successMessage = encodeURIComponent('Conta criada com sucesso! Faça o login para continuar.');
                window.location.href = `login.html?message=${successMessage}`;

            } catch (error) {
                showMessage(error.message, 'error');
                setLoading(submitButton, 'Criar a minha Conta', false);
            }
        });
    }

    // --- FUNÇÕES AUXILIARES ---
    function showMessage(text, type = 'error') {
        const container = document.getElementById('message-container');
        if (!container) return;

        let bgColor = type === 'error' ? 'bg-red-100' : 'bg-green-100';
        let textColor = type === 'error' ? 'text-red-700' : 'text-green-700';

        container.textContent = text;
        container.className = `p-4 mb-4 rounded-lg text-center font-medium ${bgColor} ${textColor}`;
        container.style.display = 'block';
    }

    function setLoading(button, text, isLoading) {
        button.disabled = isLoading;
        button.textContent = text;
        button.style.opacity = isLoading ? '0.7' : '1';
    }
});