import TelegramBot from 'node-telegram-bot-api';
import { Proposal } from './index.js';

export class TelegramService {
    private bot: TelegramBot | null = null;
    private chatId: string | undefined;
    private userId: string | undefined;
    private approvalCallback: ((proposalId: string, decision: 'approve' | 'deny', userId: string) => Promise<void>) | null = null;

    constructor() {
        const token = process.env.TELEGRAM_BOT_TOKEN;
        this.chatId = process.env.TELEGRAM_CHAT_ID;
        this.userId = process.env.TELEGRAM_USER_ID;
        const noPolling = process.env.TELEGRAM_NO_POLLING === 'true';

        if (token) {
            this.bot = new TelegramBot(token, { polling: !noPolling });
            console.log(`🤖 Telegram Bot Initialized ${noPolling ? '(Polling Disabled)' : ''}`);

            if (!noPolling) {
                this.bot.on('message', (msg) => {
                    if (msg.text === '/start') {
                        const id = msg.chat.id.toString();
                        this.bot?.sendMessage(msg.chat.id, `ClawGuard Approval Bot Online 🛡\nYour Chat ID: ${id}`);
                        if (id !== this.chatId && id !== this.userId) {
                            console.warn(`⚠️  Unauthorized user messaged bot: ${id}`);
                        }
                    }
                });

            }

            this.bot.on('callback_query', async (query) => {
                if (!query.data || !this.approvalCallback) return;

                // Security: Only allow authorized user
                const queryUserId = query.from.id.toString();
                if (queryUserId !== this.userId && queryUserId !== this.chatId) {
                    await this.bot?.answerCallbackQuery(query.id, { text: '⛔ Unauthorized', show_alert: true });
                    return;
                }

                try {
                    const [action, proposalId] = query.data.split(':');
                    if (action === 'approve') {
                        await this.approvalCallback(proposalId, 'approve', queryUserId);
                        await this.bot?.answerCallbackQuery(query.id, { text: '✅ Approved via Telegram' });
                        await this.bot?.editMessageText(`✅ Proposal ${proposalId.slice(0, 8)} APPROVED by user`, {
                            chat_id: query.message?.chat.id,
                            message_id: query.message?.message_id
                        });
                    } else if (action === 'deny') {
                        await this.approvalCallback(proposalId, 'deny', queryUserId);
                        await this.bot?.answerCallbackQuery(query.id, { text: '❌ Denied via Telegram' });
                        await this.bot?.editMessageText(`❌ Proposal ${proposalId.slice(0, 8)} DENIED by user`, {
                            chat_id: query.message?.chat.id,
                            message_id: query.message?.message_id
                        });
                    }
                } catch (err: any) {
                    console.error('Telegram Callback Error:', err);
                    await this.bot?.answerCallbackQuery(query.id, { text: `Error: ${err.message}`, show_alert: true });
                }
            });

            // Error handling
            this.bot.on('polling_error', (error) => {
                const err = error as any;
                console.error(`Telegram Polling Error: ${err.code || 'UNKNOWN'} - ${err.message}`);
                // Don't crash server on network blips
            });

        } else {
            console.warn('⚠️  TELEGRAM_BOT_TOKEN not set - Telegram approvals disabled');
        }
    }

    public setApprovalCallback(callback: (proposalId: string, decision: 'approve' | 'deny', userId: string) => Promise<void>) {
        this.approvalCallback = callback;
    }

    public async requestApproval(proposal: Proposal, instructions: string[]) {
        if (!this.bot || !this.chatId) return;

        const message = `🚨 <b>APPROVAL REQUIRED</b> 🚨\n\n` +
            `<b>Tool:</b> ${proposal.tool}\n` +
            `<b>Action:</b> ${proposal.action}\n` +
            `<b>Args Hash:</b> <code>${proposal.argsHash}</code>\n` +
            `<b>Policy Hash:</b> <code>${proposal.policyHash}</code>\n` +
            `<b>Untrusted Source:</b> ${proposal.untrustedSource || 'No'}\n\n` +
            `<i>Instructions:</i>\n${instructions.join('\n')}`;

        try {
            await this.bot.sendMessage(this.chatId, message, {
                parse_mode: 'HTML',
                reply_markup: {
                    inline_keyboard: [[
                        { text: '✅ APPROVE', callback_data: `approve:${proposal.id}` },
                        { text: '❌ DENY', callback_data: `deny:${proposal.id}` }
                    ]]
                }
            });
            console.log(`📨 Sent approval request for ${proposal.id} to Telegram`);
        } catch (err) {
            console.error('Failed to send Telegram message:', err);
        }
    }

    public async notifyExecution(proposal: Proposal, success: boolean, resultHash: string) {
        if (!this.bot || !this.chatId) return;
        const icon = success ? '✅' : '❌';
        const msg = `${icon} <b>Execution ${success ? 'Complete' : 'Failed'}</b>\n` +
            `Action: ${proposal.action}\n` +
            `Result Hash: <code>${resultHash}</code>`;

        try {
            await this.bot.sendMessage(this.chatId, msg, { parse_mode: 'HTML' });
        } catch (err) {
            console.error('Failed to send execution notification:', err);
        }
    }
}
