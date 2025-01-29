from pydantic import BaseModel, Field
from typing import Dict, Optional, List
import os
from datetime import timedelta

# Security Configuration
class SecurityConfig(BaseModel):
   secret_key: str = os.getenv('SECRET_KEY', 'default-secret-key')
   algorithm: str = 'HS256'
   access_token_expire: int = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 30))
   refresh_token_expire: int = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))
   password_min_length: int = 8
   token_url: str = "/api/token"

# Redis Configuration
class RedisConfig(BaseModel):
   url: str = os.getenv('REDIS_URL', 'redis://localhost:6379')
   max_connections: int = int(os.getenv('REDIS_MAX_CONNECTIONS', 10))
   timeout: int = int(os.getenv('REDIS_TIMEOUT', 30))
   retry_on_timeout: bool = True
   health_check_interval: int = 30
   socket_keepalive: bool = True

# Monitoring Configuration
class MonitoringConfig(BaseModel):
   enabled: bool = bool(int(os.getenv('MONITORING_ENABLED', 1)))
   url: str = os.getenv('MONITORING_URL', 'http://localhost:9090')
   interval: int = int(os.getenv('MONITORING_INTERVAL', 60))
   retention_days: int = int(os.getenv('MONITORING_RETENTION_DAYS', 7))
   metrics_path: str = "/metrics"

# API Configuration
class APIConfig(BaseModel):
   google_api_key: str = os.getenv('GOOGLE_API_KEY', '')
   eleven_labs_api_key: str = os.getenv('ELEVEN_LABS_API_KEY', '')
   eleven_labs_voice_id: str = os.getenv('ELEVEN_LABS_VOICE_ID', '')
   rate_limit_requests: int = int(os.getenv('RATE_LIMIT_REQUESTS', 100))
   rate_limit_minutes: int = int(os.getenv('RATE_LIMIT_MINUTES', 60))

# Task Configuration
class TaskConfig(BaseModel):
   max_retries: int = int(os.getenv('TASK_MAX_RETRIES', 3))
   timeout: int = int(os.getenv('TASK_TIMEOUT', 30))
   chunk_size: int = int(os.getenv('CHUNK_SIZE', 1024 * 1024))
   max_concurrent_tasks: int = int(os.getenv('MAX_CONCURRENT_TASKS', 5))
   cleanup_interval: int = int(os.getenv('TASK_CLEANUP_INTERVAL', 3600))

# Application Configuration
class AppConfig(BaseModel):
   debug: bool = bool(int(os.getenv('DEBUG', 0)))
   env: str = os.getenv('APP_ENV', 'development')
   version: str = os.getenv('APP_VERSION', '1.0.0')
   workers: int = int(os.getenv('WORKERS', 4))
   cors_origins: List[str] = os.getenv('CORS_ORIGINS', '*').split(',')
   temp_dir: str = os.getenv('TEMP_DIR', './temp')
   log_level: str = os.getenv('LOG_LEVEL', 'info').upper()

# Constants
ELEVEN_LABS_API_URL = "https://api.elevenlabs.io/v1"
GOOGLE_AI_API_URL = "https://generativelanguage.googleapis.com/v1"
DEFAULT_AUDIO_DURATION = 60
DEFAULT_VIDEO_DIMENSIONS = "width=1080&height=1920"
DEFAULT_SCENE_COUNT = 4
CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))
SESSION_SECRET = os.getenv('SESSION_SECRET', os.urandom(24).hex())

class Settings(BaseModel):
   security: SecurityConfig = SecurityConfig()
   redis: RedisConfig = RedisConfig()
   monitoring: MonitoringConfig = MonitoringConfig()
   api: APIConfig = APIConfig()
   tasks: TaskConfig = TaskConfig()
   app: AppConfig = AppConfig()

# Initialize configurations
SECURITY_CONFIG = SecurityConfig()
REDIS_CONFIG = RedisConfig()
MONITORING_CONFIG = MonitoringConfig()
API_CONFIG = APIConfig()
TASK_CONFIG = TaskConfig()
APP_CONFIG = AppConfig()

def get_settings() -> Settings:
   return Settings()

# توليد المواضيع - المهمة 1
task_1_prompt = """
Task 1 Prompt:

Objective: Act as an experienced YouTube Shorts creator. Brainstorm and come up with engaging and relevant topics for YouTube Shorts videos about {topic}.

You are an expert storyteller with profound knowledge of historical anecdotes, Islamic history, and Arabic literature. Craft an engaging and vivid retelling of a story from the following themes:

Clever Judges in History: Narratives that demonstrate the wisdom and wit of judges in delivering justice.
Humorous and Witty Arabs: Amusing anecdotes and clever quips from Arab culture.
Intelligence of the Companions: Remarkable tales showcasing the intelligence and foresight of the Prophet Muhammad's Companions.
Caliphs and Ministers: Stories highlighting the wit and diplomacy of rulers and their advisors.
Arabs of the Desert: Captivating accounts of the wisdom and sharp wit of Bedouins.
Ordinary People’s Wit: Everyday acts of intelligence and intuition by common folk.
Doctors' Cunning: Stories of quick-thinking and resourceful medical professionals.
Women’s Wisdom: Anecdotes showcasing the cleverness and perception of women.
Start by stating the theme and title of the story. Use descriptive language, cultural references, and dialogue to bring the story to life while ensuring it is engaging and reflective of the culture and era it originated from.

Each topic should be unique, attention-grabbing, and cater to the interests of the target audience. Consider incorporating trending themes or challenges to increase the videos' chances of going viral. Ensure that the topics are suitable for the short-form video format and can be easily executed within the constraints of YouTube Shorts.

Comprehensive Guide for Crafting an Effective Brainstorm to Achieve a Professional Level in Content Creation:

To achieve a professional level in creating content and achieving high search visibility, several key factors must be considered. Here is a detailed list of these factors:

Clearly Define the Objective:

Objective: Specify the goal you want to achieve (e.g., increasing audience engagement, driving traffic to a website, educating on a specific topic).

Example: If you are writing a scientific article, clearly define the topic and scope.

Identify the Target Audience:

Target Audience: Who are the people who will read or watch this content? Define their demographic, interests, and needs.

Example: If you are writing for a scientific community, define their level and basic knowledge.

Determine the Tone and Style:

Tone: What tone do you want to use (formal, informal, etc.)?

Style: What style do you want to use (formal, informal, scientific, narrative, etc.)?

Identify Essential Elements:

Essential Elements: What are the key elements that must be included in the content (facts, storytelling techniques, visual or audio cues)?

Example: In a scientific article, you might want to include theories, previous research, and new findings.

Identify Resources:

Resources: What resources will you use for research and review (books, articles, videos, interviews, etc.)?

Example: Books, scientific articles, reliable websites, etc.

Set Criteria:

Criteria: What criteria must the content meet (engagement, educational value, SEO compliance)?

Example: Should the content be free of grammatical and linguistic errors? Should it comply with certain standards?

Set a Timeline:

Timeline: When should the content be completed and published?

Example: When should the content be ready for publication or review?

Identify Tools and Techniques:

Tools and Techniques: What tools will you use to create the content (video editing software, SEO tools, content management systems)?

Example: Text editing software, project management tools, scientific research tools, etc.

Set Quality Standards:

Quality Standards: What quality standards must the content meet (originality, research-backed)?

Example: Should the content be original? Should it be reliable and supported by evidence?

Identify Legal and Ethical Constraints:

Legal and Ethical Constraints: What legal and ethical constraints must be considered (copyright, privacy, etc.)?

Example: Should the content be free of any copyright violations or privacy issues?

Identify Distribution Channels:

Distribution Channels: Where will you distribute your content (YouTube, social media, blogs, etc.)?

Example: Websites, social media platforms, scientific journals, etc.

Define Review and Proofreading Steps:

Review and Proofreading: How will the content be reviewed for grammar, facts, and audience appeal?

Example: Review for grammar and language, review for rights, review for standards.

Define Audience Interaction:

Audience Interaction: How will you engage with your audience?

Example: Responding to comments, creating feedback loops.

Define Measurement and Evaluation:

Measurement and Evaluation: How will you measure and evaluate the success of the content (views, shares, engagement)?

Example: Number of views, number of shares, audience ratings, etc.

Additional Factors for Professional Content Creation:

Understand the Target Audience:

Demographic Analysis: Age, gender, geographic location, and interests.
Search Behavior: When, where, and how does the audience search?
Keyword Analysis:

Use keyword analysis tools like Google Keyword Planner, Ahrefs, SEMrush to choose the right keywords.
Quality and Viral Content:

Focus on creating high-quality, engaging, and shareable content.
Make sure your content has the potential to go viral.
Search Engine Optimization (SEO):

Optimize titles, descriptions, and meta tags.
Use internal and external links for better visibility.
Brand Building:

Develop your Unique Selling Proposition (USP).
Build trust and credibility with your audience.
Trend Responsiveness:

Stay up-to-date with trends and competitors.
Be quick to respond to audience preferences and content trends.
Continuous Learning and Development:

Attend workshops, join communities, and stay updated on best practices.
Your output should only suggest 3 viral topics:

Topic 1
Topic 2
Topic 3

"""

# تحليل الاتجاهات - المهمة 2
task_2_prompt = """
As an experienced YouTube Shorts creator, the goal is to research and suggest trending topics in a {niche} focusing on thrilling historical narratives, crime stories, and incredible real-life events. The topic should appeal to an audience interested in captivating, authentic stories that are both engaging and intriguing.

Detailed Outline for YouTube Shorts Content Creation:
1. Define the Objective:
Primary Objective: Increase viewership and engagement on YouTube.
Target Audience: Enthusiasts of history and true crime, those who enjoy real-life stories, and fans of short, engaging content on YouTube Shorts.
Type of Content: Short-form videos (Shorts) that delve into true historical and crime stories.
2. Define the Niche:
Specific Niche: True historical and crime stories that are intriguing and captivating.
Types of Content: Stories involving history, crime, humor, mystery, and other short, interesting tales that evoke emotion or curiosity.
3. Research Trending Topics:
Primary Sources:
Google News: Search for keywords such as "true historical stories," "historical crimes," and "real-life mysteries."
Reddit: Check out subreddits like r/truecrime, r/history, and r/shortstories.
Social Media:
Twitter: Use hashtags such as #TrueCrime, #History, and #RealLifeStories.
Instagram: Follow accounts dedicated to true historical and crime stories.
YouTube: Analyze channels focused on similar niches.
Secondary Sources:
Quora: Participate in discussions or read answers about true historical and crime stories.
Specialized Forums: Explore forums dedicated to history and crime-related topics.
4. Analyze Trends and Engagement:
Google Trends: Identify trending topics through key terms.
YouTube Analytics: Analyze similar videos to see what content performs well.
Social Media Insights: Use analytics tools to track engagement on platforms like Twitter and Instagram.
5. Determine Professional Elements:
Video Quality:

Quality: Use high-quality cameras and clear audio.
Editing: Employ professional editing software for polished production.
Cultural and Historical References:

Historical References: Rely on credible sources like historical books or official websites.
Local Culture: Incorporate cultural references relevant to the audience.
Dialogue and Engagement:

Questions: Pose questions at the end of videos to encourage viewer interaction.
Call to Action: Prompt viewers to like, share, and subscribe.
Dramatic Build-Up:

Suspense: Use dramatic editing techniques to build tension.
Dialogue: Include engaging dialogue to make the story more captivating.
6. Craft the Prompt:
Clarity: Ensure the prompt is clear and specific.
Detail: Provide a detailed structure for creating content.
Relevance: Use examples to make the prompt relatable to the target audience.
Example of a Professional Prompt:

"You are an expert in creating engaging short-form videos that dive deep into true historical and crime stories. Utilize the following sources to identify trending topics:

Google News: Keywords like 'true historical stories,' 'historical crimes,' and 'real-life mysteries.'
Reddit: Subreddits like r/truecrime, r/history, and r/shortstories.
Twitter: Hashtags such as #TrueCrime, #History, and #RealLifeStories.
Instagram: Accounts that share true historical and crime stories.
YouTube: Channels focusing on similar niches.
Google Trends: Use key terms to uncover trending topics.
YouTube Analytics: Review the performance of related videos.
Social Media Insights: Track engagement using social media analytics tools."
7. Review and Improve:
Review Content: Regularly assess content to ensure it aligns with the objective.
Improve Engagement: Use engagement metrics to refine content and presentation.
Continuous Improvement: Adjust strategies based on feedback and performance data.
Suggested Topic:
The Story of the Legendary Escape from Alcatraz Prison (1962):

Theme: Historical Crime Story Why It's Trending: The escape from Alcatraz is one of the most infamous and mysterious events in criminal history. The daring attempt, featuring three prisoners who seemingly disappeared without a trace, continues to intrigue people today. It's filled with suspense, unanswered questions, and an element of mystery that makes it perfect for a YouTube Shorts format.
"""

task_3_prompt = """ 
Act as an experienced YouTube Shorts creator. Brainstorm and suggest interactive questions that you can ask your viewers about {Analyse_Trends} to increase engagement and create a sense of community. The questions should be thought-provoking, relevant, and encourage viewers to comment, like, and share the video. Consider incorporating open-ended questions, polls, or challenges to spark conversation and keep viewers coming back for more. Additionally, ensure that the questions align with your content and brand voice to maintain authenticity and connection with your audience.
"""

task_4_prompt = """
Craft a compelling narrative that intertwines thrilling historical events with elements of mystery and crime. Focus on {Analyse_Trends} Focus on a distinctive real-life event or figure that evokes strong emotions or inspires the audience. Utilize vivid descriptions, character development, and dramatic tension to create a captivating story that may include themes of perseverance, ingenuity, or moral ambiguity.

Consider the following guidelines:

Here’s a detailed list of all factors and precise elements for crafting a professional and perfect guidelines for writing stories or texts:

Defining the Framework
Description:
The framework is the foundation of the story, establishing who the characters are, what the story is about, and where and when it takes place.
How to Specify:

Who? Identify the main characters.
What? Define the central idea or conflict.
Where? Choose the setting (real or fictional).
When? Determine the timeline (past, present, future).
Role:
Provides a clear base for the story and serves as a reference for other elements.
Characters
Description:
Characters are the driving force of the story. The more detailed and intriguing they are, the stronger the narrative.
How to Specify:

Name: Ensure the name reflects the character or their environment.
Physical Traits: Appearance, height, hair, eyes.
Backstory: The events that shaped the character’s life.
Motivations: What does the character want and why?
Strengths and Weaknesses: Make them relatable with human flaws.
Role:
Creates an emotional connection with the audience and brings the characters to life.
World-Building
Description:
Describing the environment where events occur in a way that immerses the reader in the story’s reality or magic.
How to Specify:

Geography: Is it a desert, mountainous area, or futuristic city?
Culture: Traditions, customs, language.
Social and Political System: Democracy or dictatorship?
Resources and Technology: Level of development.
Role:
Makes the world logical and captivating, allowing the reader to fully engage.
Story Structure and Flow
Description:
The pattern that events follow from beginning to end.
How to Specify:

Beginning: Start with a hook to grab attention.
Rising Action: Gradually increase the complexity of challenges.
Climax: The moment of peak tension and conflict.
Ending: Decide on a type of conclusion (closed or open-ended).
Role:
Maintains the reader’s attention and creates a smooth narrative flow.
Tone and Style
Description:
Tone defines the overall feel of the story, while style is the manner of narration.
How to Specify:

Tone: Is it dramatic, humorous, or dark?
Style: Direct or literary with metaphors?
Narration Style: From the narrator’s or characters’ perspectives?
Role:
Affects the reader’s experience and the story’s mood.
Sensory Details
Description:
Detailed descriptions involving the five senses (sight, sound, touch, smell, taste).
How to Specify:

Sight: Describe colors, lighting, appearances.
Sound: Surrounding noises, dialogues.
Touch: Texture, temperatures.
Smell: Scents.
Taste: Foods and drinks.
Role:
Makes the reader feel immersed in the story.
Subplots
Description:
Side stories that add depth and intrigue to the main narrative.
How to Specify:

A complex romantic relationship.
A hidden secret revealed at a critical moment.
A secondary conflict that enhances the characters.
Role:
Increases suspense and character depth.
Timeline
Description:
The way events are presented.
How to Specify:

Linear Timeline: Events in chronological order.
Flashback: Returning to past events.
Parallel Timeline: Two stories progressing simultaneously.
Time Manipulation: Blending past, present, or future.
Role:
Impacts how the reader understands events and adds excitement.
Symbolism
Description:
Elements in the story that carry deeper meanings.
How to Specify:

Objects: A book, a flower, a sword.
Colors: Each color represents something.
Events: A storm symbolizing anger or change.
Role:
Adds hidden meanings and enriches the story.
Ending
Description:
The conclusion summarizes the story’s message or leaves the reader pondering.
How to Specify:

Closed Ending.
Open Ending.
Unexpected Twist or Reversal.
Role:
Leaves a lasting impression on the reader.
Audience Customization
Description:
Tailoring the story to suit the interests and age of the target audience.
How to Specify:

Age Group: Children, teens, adults.
Interests: Drama, sci-fi, horror.
Culture: Use cultural references familiar to the audience.
Role:
Makes the story more appealing and impactful.
Plot Twists
Description:
Unexpected turns in the story that alter events dramatically.
How to Specify:

Defy expectations.
Reveal an unexpected truth.
Switch roles between hero and villain.
Role:
Keeps the reader on edge and enhances suspense.
Iteration and Refinement
Description:
Testing multiple prompts and improving based on outcomes.
How to Specify:

Compare results and identify improvement points.
Add details or remove unnecessary elements.
Role:
Ensures the story reaches its highest quality.
Conclusion:
Using all these factors ensures a high-quality, professional prompt. Focusing on precise details makes the story richer and more engaging. Continuous improvement through iteration is key to perfection.
Linguistic Proofreading and Word Vocalization (Tashkeel)
Description:
This factor focuses on ensuring the correctness of the language used in terms of spelling and grammar while adding diacritical marks (Tashkeel) to guarantee proper pronunciation and the intended tone.
How to Specify:

Proofreading:
Use linguistic proofreading tools and software to check for spelling and grammatical errors.
Manually review the text, especially in sensitive linguistic contexts.
Vocalization (Tashkeel):
Fully vocalize words (Damma, Fatha, Kasra, Sukoon) to ensure pronunciation clarity.
Focus on words that might cause ambiguity in meaning if not vocalized.
Ensure that the vocalization reflects the intended tone (dramatic, humorous, serious, etc.).
Role:
Guarantees text clarity and removes any ambiguity caused by errors or the lack of vocalization.
Enhances the reader's or listener's experience, especially when converting text to speech using automated pronunciation technologies.
Improves the aesthetic quality of the text, making it more professional, particularly in literary or formal contexts.
Importance of Tashkeel:
Helps improve the quality of speech delivery if the text is to be used for voice generation.
Ensures the correct meaning of words, especially in Arabic, where meaning can change based on vocalization.
Summary of the New Addition:
Adding the factor of linguistic proofreading and Tashkeel makes the text more professional and ensures accurate pronunciation and tone, thereby enhancing the quality of both written and spoken texts.

Instructions for Crafting the Story:

Select a real-life historical event or figure, ensuring it has elements of intrigue or crime.
Provide rich contextual details that immerse the reader in the time period and setting.
Develop relatable characters who experience significant challenges or moral dilemmas.
Use a narrative structure that builds suspense and leads to a compelling climax.
Conclude with a resolution that leaves the audience with a thought-provoking message or emotional impact. like that {Engagement}
Aim for a word count between 520 to 1500 words to allow for depth and exploration of themes.
Examples of themes to explore may include:

The ingenuity and tenacity of innovators like the Wright brothers.
The moral complexities surrounding figures like Ed Gein.
The human spirit's resilience as exemplified in the rescue of the Chilean miners.
The cunning and strategic planning involved in notable heists like the Hatton Garden Jewelry Theft.
Ensure the story is both informative and engaging, appealing to readers' emotions and curiosity.

Goal:
Craft a creative storytelling fully in Arabic.
Make sure the script contains no scene directions, visual cues, or instructions—just the narrative.
YouTube Documentary stories Shorts video story that lasts approximately between 1 and 5 minutes.







"""

task_5_prompt = """


إليك النص الذي طلبته بشكل منسق وصحيح:

---

**task_5_prompt**

"Act as an expert in SEO keyword research and as an experienced YouTube Shorts creator. Your task is to write optimized long-tail keywords for a YouTube Short video, utilizing relevant keywords to improve searchability and reach. Create a list of 12 long-tail keywords specifically tailored for a YouTube Short video on {niche}. YouTube Shorts Analyze Trends on: {Analyse_Trends}. The YouTube Scripts of this video is {Script}. Your keywords should be highly relevant, low in competition, and likely to attract organic traffic, utilizing relevant keywords related to content to drive traffic and increase visibility. Use advanced SEO tools and techniques to identify these keywords. The response must be limited to a maximum of 500 characters, and formatted as follows: long-tail keywords, word, long-tail keywords."

---

**عوامل و خطوات لتحسين تحسين محركات البحث (SEO) وتعزيز وضوح المحتوى وأدائه على منصات مثل Google و YouTube و Bing وغيرها:**

1. **العوامل الرئيسية لتحسين SEO**

   - **الكلمات الرئيسية طويلة الذيل**:
     - **الوصف**: الكلمات الرئيسية طويلة الذيل هي كلمات أطول وأكثر تحديدًا، تستهدف استفسارات بحث أقل تنافسية.
     - **الاستخدام**: استخدم الكلمات الرئيسية طويلة الذيل في العناوين، الأوصاف، ومحتوى الفيديو.
     - **الأدوات**: Google Keyword Planner، Ahrefs، Ubersuggest.

   - **العنوان والوصف**:
     - **الجاذبية**: اجعل العنوان والوصف جذابًا وملائمًا.
     - **الدقة**: تأكد من أن العنوان دقيق وواضح، مع التركيز على الكلمات الرئيسية.
     - **الطول**: يفضل أن يتراوح طول العنوان بين 40-70 حرفًا.
     - **الروابط**: أضف روابط ذات صلة إلى محتوى آخر على موقعك أو مصادر موثوقة.

   - **الصورة المصغرة**:
     - **الجاذبية**: أنشئ صورة مصغرة جذابة وعالية الجودة.
     - **الملائمة**: استخدم صورة تمثل محتواك بدقة.
     - **الكلمات الرئيسية**: إذا كان ذلك ممكنًا، أضف كلمات رئيسية في الصورة المصغرة.

   - **النصوص المترجمة**:
     - **الجودة**: تأكد من أن النص مترجم بدقة وبهيكل مناسب.
     - **الكلمات الرئيسية**: أضف الكلمات الرئيسية الأساسية في النص.
     - **الطول**: اجعل النص تفصيليًا وشاملًا.

   - **التقييمات والمراجعات**:
     - **التعليقات الإيجابية**: اعمل على الحصول على تقييمات إيجابية.
     - **التفاعل**: شجع المشاهدين على ترك تعليقات وتقييمات إيجابية.

   - **الروابط الداخلية**:
     - **الوصف**: تساعد الروابط الداخلية في تحسين الظهور وزيادة التفاعل بين صفحاتك.
     - **الاستخدام**: أضف روابط داخلية إلى المحتوى المتعلق على موقعك.

   - **الروابط الخارجية**:
     - **الوصف**: الروابط الخارجية إلى المصادر الموثوقة تعزز المصداقية.
     - **الاستخدام**: أضف روابط إلى مصادر موثوقة مثل Wikipedia و Google Trends وغيرها.

   - **الكلمات الرئيسية ذات الدلالة الدلالية (LSI)**:
     - **الوصف**: تساعد كلمات LSI في فهم المحتوى بشكل أفضل.
     - **الاستخدام**: أضف كلمات LSI في المحتوى.

   - **تحسين السرعة**:
     - **الوصف**: تؤثر سرعة الصفحة على تجربة المستخدم وتصنيفات البحث.
     - **الأدوات**: Google PageSpeed Insights، Lighthouse.

   - **تجربة المستخدم**:
     - **الوصف**: تجربة المستخدم الجيدة تحسن التفاعل والظهور.
     - **الجودة**: تأكد من أن المحتوى عالي الجودة ومنظم بشكل جيد.

2. **خطوات التنفيذ**

   - **تحديد الكلمات الرئيسية**:
     - **الأدوات**: Google Keyword Planner، Ahrefs، Ubersuggest.
     - **الإجراء**: ابحث وحدد الكلمات الرئيسية ذات الصلة.
     - **التنفيذ**: استخدم الكلمات الرئيسية في العناوين، الأوصاف، ومحتوى الفيديو.

   - **تحسين العنوان والوصف**:
     - **الإجراء**: اجعل العنوان والوصف دقيقين وجذابين وغنيين بالكلمات الرئيسية.
     - **الأدوات**: Google Search Console، YouTube Analytics.

   - **تحسين الصورة المصغرة**:
     - **الإجراء**: أنشئ صورة مصغرة جذابة وملائمة.
     - **الأدوات**: Canva، Adobe Spark.

   - **تحسين النص المترجم**:
     - **الإجراء**: تأكد من أن النص مترجم بدقة وغني بالكلمات الرئيسية.
     - **الأدوات**: YouTube Analytics.

   - **تعزيز التقييمات والمراجعات**:
     - **الإجراء**: شجع على التقييمات والمراجعات الإيجابية.
     - **الأدوات**: YouTube Analytics.

   - **إضافة الروابط الداخلية**:
     - **الإجراء**: أضف روابط إلى محتوى ذي صلة على موقعك.
     - **الأدوات**: GoogleSearchConsole، Ahrefs.

   - **إضافة الروابط الخارجية**:
     - **الإجراء**: أضف روابط إلى مصادر موثوقة.
     - **الأدوات**: GoogleSearchConsole، Ahrefs.

   - **استخدام كلمات LSI**:
     - **الإجراء**: أضف كلمات LSI في المحتوى.
     - **الأدوات**: Ahrefs، Ubersuggest.

   - **تحسين السرعة**:
     - **الإجراء**: استخدم الأدوات لتحسين سرعة الصفحة.
     - **الأدوات**: Google PageSpeed Insights، Lighthouse.

   - **تعزيز تجربة المستخدم**:
     - **الإجراء**: تأكد من أن المحتوى عالي الجودة وجذاب.
     - **الأدوات**: Hotjar، Lighthouse.

3. **الأدوات**

   - **Google Keyword Planner**:
     - **الوصف**: يساعد في العثور على الكلمات الرئيسية ذات الصلة.
     - **الاستخدام**: تحديد الكلمات الرئيسية للمحتوى.

   - **Ahrefs**:
     - **الوصف**: يساعد في البحث عن الكلمات الرئيسية وتحليل الروابط.
     - **الاستخدام**: تحديد الكلمات الرئيسية وتحليل الروابط.

   - **Ubersuggest**:
     - **الوصف**: يساعد في العثور على الكلمات الرئيسية ذات الصلة.
     - **الاستخدام**: تحديد الكلمات الرئيسية للمحتوى.

   - **Google PageSpeed Insights**:
     - **الوصف**: يساعد في تحسين سرعة الصفحة.
     - **الاستخدام**: تحسين سرعة الصفحة لتحقيق أداء أفضل.

   - **Google Search Console**:
     - **الوصف**: يساعد في مراقبة وتحسين ظهور البحث.
     - **الاستخدام**: مراقبة وتحسين ظهور البحث.

   - **YouTube Analytics**:
     - **الوصف**: يساعد في مراقبة وتحسين أداء الفيديو.
     - **الاستخدام**: مراقبة وتحسين أداء الفيديو.

   - **Canva**:
     - **الوصف**: يساعد في إنشاء صور مصغرة عالية الجودة.
     - **الاستخدام**: تصميم صور مصغرة جذابة.

   - **Adobe Spark**:
     - **الوصف**: يساعد في إنشاء صور مصغرة عالية الجودة.
     - **الاستخدام**: تصميم صور مصغرة جذابة.

   - **Hotjar**:
     - **الوصف**: يساعد في تحسين تجربة المستخدم.
     - **الاستخدام**: مراقبة سلوك المستخدم وتحسين تجربة المستخدم.

   - **Lighthouse**:
     - **الوصف**: يساعد في تحسين تجربة المستخدم.
     - **الاستخدام**: مراقبة وتحسين تجربة المستخدم.

---

**تنفيذ هذه العوامل والخطوات سيساعدك بشكل كبير على تحسين SEO وزيادة وضوح وأداء محتواك على محركات البحث المختلفة والمنصات.**

---

**#Output Format**

**Explanation of this Prompt**
- **Task Clarity**: Specifies that you want a keyword list specifically for YouTube SEO purposes.
- **Language Arabic Constraint**: Ensures that the output keywords, formatted in a list, and meets the 500-character limit.
- **Make sure output keywords in Arabic**: Ensure keywords are specific and targeted for Arabic-speaking regions.
- **Character limit**: Ensure the output does not exceed 500 characters, formatted as: long-tail keywords, word, long-tail keywords.
"""

task_6_prompt = """


بالطبع! إليك النص المنسق بشكل صحيح:

---

**Task 6 Prompt:**

```markdown
As an experienced YouTube shorts creator, your task is to write an optimized description for a YouTube Short video on {Analyse_Trends}. The SEO keyword of the video is {keyword}. The text content script of the video is {Script}. The description should be concise yet informative, utilizing relevant keywords to improve searchability and reach. It should provide a brief overview of the video content, enticing viewers to watch. Include any relevant calls to action, such as liking, commenting, or subscribing, to encourage viewer engagement. Additionally, consider incorporating hashtags and links to other related content to drive traffic and increase visibility. Ensure the description is engaging, informative, and aligns with the overall theme and message of the video.

### **Essential Factors for Optimizing Video Descriptions on YouTube to Achieve Professional Results:**

#### **1. Keywords**
- Include targeted keywords naturally in the description, avoiding keyword stuffing.
- Use tools to find trending keywords related to your topic:
  - [Google Keyword Planner](https://ads.google.com/intl/en_us/home/tools/keyword-planner/)
  - [TubeBuddy](https://www.tubebuddy.com/)
  - [VidIQ](https://vidiq.com/)

#### **2. Professional Video Description**
- Write a clear and engaging description that explains the video content effectively.
- Divide the description into easy-to-read paragraphs.
- Start with a strong introduction that summarizes the video and grabs attention.
- Add specific details about the points covered in the video.

#### **3. Links**
- Include relevant links to sources and references used in the video:
  - Links to articles or websites that provide more information on the topic.
  - Links to related videos on your channel to enhance viewer experience and increase watch time.
- Add a subscription link, such as:
  `https://www.youtube.com/c/YourChannelName?sub_confirmation=1`

#### **4. Channel Introduction**
- Add a brief paragraph in the description about your channel, including:

    - **Channel Name:** "سوالف بهلول"
    - **Channel ID:** [https://www.youtube.com/@user-abotalalalhamrani](https://www.youtube.com/@user-abotalalalhamrani)
    - **Channel Niche:** [As a professional storyteller with extensive experience in creating captivating narratives for specializing in weaving thrilling historical tales, mysteries, and crime stories grounded in real historical events, a distinctive and interesting real-life event or story. Example of stories: 
      1- The story of the Wright brothers and the invention of the airplane 
      2- The story of Dennis Hope and the sale of lands on the moon 
      3- The story of Robert Smalley and his fatal misunderstanding 
      4- The story of the rescue team of 33 Chilean miners 
      5- The story of Ed Gein and the horror crimes 
      6- The story of Yuri Gagarin and the first space flight 
      7- The story of Hugh Glass and his survival
      8- The story of the monk Rasputin 
      9- The story of Alan Turing and the calculator 
      10- The story of Babalon “Papi” Levens 
      11- Exciting and strange true stories 
      12- The legendary escape from Alcatraz prison (1962) 
      13- The famous robbery of the Société Générale Bank (1976) 
      14- The escape from “cell 139” in Saint Quentin prison (1934) 
      15- Citibank hacking operation (1994) 
      16- Hatton Garden Jewelry Theft (2015) 
      17- The Quentin Brothers escape from Tokyo prison (2016)
      18- The “Brinks Matt” Theft (1983) 
      19- El Chapo’s Escape (2015) 
      20- Stories about the smartest and biggest thefts of the era 
      21- Stories about the biggest hacks.
      These are just examples so you can understand what type of Niche it is and make the appropriate suggestion
      A story that inspires or arouses emotions]  
    - **The niche or specialty of your channel.**
    - **The value your channel provides to viewers.**
    - **The type of content & Niche (e.g., summaries, tutorials, reviews).**

#### **5. Timestamps**
- Include timestamps to divide the video into specific sections:
  - Facilitate navigation through the video.
  - Improve user experience and increase viewer engagement.
  - Example:
    ```
    0:00 Introduction
    1:15 Point 1
    3:30 Point 2
    5:45 Conclusion
    ```

#### **6. Call-to-Action (CTA) Phrases**
- Add phrases that encourage viewers to interact:
  - "Don’t forget to like the video and subscribe to the channel!"
  - "Leave your thoughts in the comments!"
  - "Watch the related videos linked below for more information!"

#### **7. Hashtags**
- Include 2-3 relevant hashtags to improve the video's visibility in search results.
- Example:
  - #MovieSummaries
  - #HorrorStories
  - #Action

#### **8. SEO Text Optimization**
- Focus on including natural user query phrases.
- Use words like "how," "best," "tutorial," "summary," etc.
- Pay attention to the natural repetition of keywords within the description.

#### **9. Channel and Video References**
- Include references to previous videos in the description.
- Example: "Also watch: [Title of previous video and link]".

#### **10. Regular Description Updates**
- Update the description periodically to add new information or improve keywords.

---

### **Template for a Professional Video Description:**

```markdown
🎬 **[Video Title]**
Welcome to a new video on our channel! In this video, we will discuss [brief summary of the topic]. We will cover the following points:
- [Point 1]
- [Point 2]
- [Point 3]

📝 **Useful Sources and Links:**
- [Link to source/article 1]
- [Link to source/article 2]

📺 **Related Videos:**
- [Title of previous video and link]
- [Title of similar video and link]

📌 **About Our Channel:**
Our channel specializes in [niche/specialty], providing [type of content]. If you are a fan of [topic], don't forget to subscribe to our channel for the latest videos!

🔔 **Follow Us on Social Media:**
- [Instagram account link]
- [Twitter account link]

⏱️ **Timestamps:**
0:00 Introduction
1:20 Point 1
3:15 Point 2
5:40 Conclusion

💬 **Share Your Thoughts:**
What do you think of this video? Do you have any suggestions? Leave a comment below!

#MovieSummaries #HorrorStories #Action
```

---

### **Important Resources for Improving Video Descriptions and SEO on YouTube:**
1. [YouTube Help - Write effective descriptions](https://support.google.com/youtube/answer/6373554)
2. [TubeBuddy Blog - Video Description Tips](https://www.tubebuddy.com/blog/)
3. [VidIQ Blog - YouTube SEO Best Practices](https://vidiq.com/blog/)
4. [Neil Patel - YouTube SEO Guide](https://neilpatel.com/blog/youtube-seo/)

By following these essential factors and using the provided template, you can ensure that your video content appears effectively and stands out in YouTube search results.
```

---

**Output Format:**

- **Explanation of this Prompt**
- **Task Clarity**: Specifies that you want a Video Description specifically for YouTube SEO purposes.
- **Language Arabic Constraint**: Ensures that the output Video Description, formatted, and meets the 5000-character limit.
- **Make sure output Video Description in Arabic**.
- **Make sure output Video Description Specific and targeted in Arabic especially in Arab geographical regions**.
- **Must be limited to a maximum of 5000 characters, and formatted Professional Video Description**.
"""


# اقتراح العنوان - المهمة 7


task_7_prompt = """Act as an experienced YouTube shorts creator and suggest SEO-friendly titles for a short video about {Analyse_Trends}. The text content script of the video is {Script}. Based on SEO, use these keywords: {keyword}. The titles should be attention-grabbing, concise, and optimized for search engines to increase the video's visibility and reach. Consider relevant keywords, trending topics, and audience interests to come up with compelling titles that will attract viewers and improve the video's discoverability on YouTube. Additionally, ensure that the titles accurately reflect the content of the video to maintain viewer trust and engagement.

### Essential Factors for Optimizing SEO and Creating a Professional YouTube SEO Title for the Best Results on YouTube and Ensuring Regular Content Suggestions:

#### Essential and Precise Factors for Optimizing the Title (YouTube SEO Title) Professionally:
Optimizing the title is one of the most crucial steps in enhancing search engine optimization (SEO) for YouTube videos. The title is the first thing users and search engines notice, so it must be attractive, specific, and supported by targeted keywords.

1. **Target Audience Analysis:**
   - Identify the age group, geographic location, and interests of your target audience.
   - Research keywords that your target audience searches for.
   - Focus on long-tail keywords that are relevant.
   - Use keywords in the title, description, and tags.

3. **Optimizing the Title (YouTube SEO Title):**
   - Create attractive titles that include primary keywords.
   - Keep the title length between 50-60 characters.
   - Add elements that attract attention:
     - Numbers (e.g., "Top 5 Movies...").
     - Curiosity-inducing words (e.g., "Unexpected," "Must-Watch").
     - Time indicators (e.g., "In 2024").

   **Title Templates:**
   - "How to [Keyword] in [Year]? | Secrets You Didn't Know!"
   - "[Keyword]: The Best Tips to Achieve [Goal] Quickly!"
   - "Discover [Feature/Product] - [Keyword] in the Simplest Way!"

4. **Optimizing the Description (YouTube SEO Description):**
   - Start with a short paragraph that grabs attention and includes keywords.
   - Include a clear summary of what the video offers.
   - Add relevant links:
     - Links to external sources or previous videos.
     - Links to social media networks or the official website.
   - Place relevant hashtags (#) at the end of the description.

   **Description Template:**
   - First Paragraph: "Want to know [what the video offers]? In this video, we will discuss [keyword] in an easy and simplified manner suitable for everyone!"
   - Second Paragraph: "If you are looking for [benefit/information] in a concise way, this video is exactly what you need. Don't forget to subscribe and enable the bell to follow all the latest updates!"
   - Links:
     - "📌 Watch more: [Link to previous video]"
     - "Follow us on Instagram: [Link to the account]"
   - Hashtags: #Keyword #YouTubeSEO #Shorts

5. **Creating Thumbnails (Thumbnails):**
   - Use an attractive and custom design for each video.
   - Ensure clear visual texts with contrasting colors.
   - Include clear facial expressions or engaging symbols.

6. **Content Optimization:**
   - Ensure the video meets the purpose or question the user is searching for.
   - Place the keyword in the first 15 seconds of the video.
   - Add end screens and cards to encourage viewers to watch more content.

7. **Adding Tags:**
   - Use keywords in the tags.
   - Add related and synonymous keywords (LSI Keywords).
   - Include tags that represent the video's topic and target audience.

8. **Promotion and Engagement:**
   - Share the video on social media.
   - Respond to comments to enhance engagement.
   - Improve click-through rate (CTR) by updating the title and description if they do not achieve the desired results.

9. **Continuous Analysis and Improvement:**
   - Review performance data using YouTube Analytics:
     - Click-through rate (CTR).
     - Watch time.
     - Audience retention.
   - Modify content based on performance.

### Points to Consider for Creating a Professional Prompt:
**Specific Goal:**
   - "I want a video to appear in the first search results when searching for [keyword].."

**Technical Details:**
   - Title length.
   - Keywords.
   - Tone (e.g., motivational, educational, suspenseful).

**Description Style:**
   - Simple and clear language.
   - Elements that encourage the viewer to click (Call to Action).

**Examples and Similar Results:**
   - "I want it to appear like [specific channel/video]."

**Target Audience:**
   - Age group and geographic location.

**Prompt Template:**
   - "Create an attractive video title about [keyword] that includes keywords like [list of keywords], and targets an audience ranging in age from [age] in [location]. Add a description containing [number of words] that highlights the main benefit of the video with important links and hashtags."

### Summary:
To achieve a professional level in SEO optimization and setting up your YouTube channel, focus on:

- Appropriate keywords.
- Attractive and optimized titles and descriptions.
- Professional thumbnail design.
- Creating content that meets the audience's needs.
- Continuously analyzing and improving performance based on data.

### 1. Using Primary Keywords:
- Identify a primary keyword or phrase that fits the video content and search expectations.
- Place the primary keyword at the beginning of the title for higher ranking in search results.
- Example:
  - "Best Ways to [Keyword] for Beginners"
  - "How to [Keyword] Easily in 2024"

### 2. User-Oriented Title:
- Focus on what the user is searching for and how to provide direct value.
- Add attention-grabbing elements:
  - Questions: "Do You Know How to [Keyword] Correctly?"
  - Numbers: "Top 5 Ways to [Keyword] That Will Change Your Life!"
  - Direct promises: "Learn [Keyword] Step by Step".

### 3. Optimal Title Length:
- Keep the title within 50-60 characters to ensure it appears fully in search results.
- If the title exceeds this length, place the keywords at the beginning.

### 4. Clickbait Elements:
- Use curiosity-inducing words while maintaining credibility, such as:
  - "You Won't Believe the Results!"
  - "A Secret No One Told You Before."
- Add a time factor:
  - "In Less Than 5 Minutes."
  - "Before the End of 2024."

### 5. Specialization and Targeting:
- Use specialized titles instead of general ones.
- Example:
  - Instead of: "Best Tips for Success"
  - Use: "Top 3 Tips to Increase Productivity While Working from Home".

### 6. Power Words in the Title:
- Include motivational words such as:
  - "Best"
  - "Easiest"
  - "Fastest"
  - "Secret"
  - "Free"
- Example:
  - "The Best Secret Way to [Keyword] for Free in 2024".

### 7. User Language:
- Speak in the language of the target audience using their everyday expressions and terminology.
- Avoid complex technical terms if the audience is not specialized.
- Example:
  - "How to Create a Successful YouTube Video for Beginners?"
  - Instead of:
  - "Steps to Optimize a Video on YouTube for Professionals".

### 8. Mobile Optimization:
- Most views come from mobile devices, so the title must be clear and concise for small screens.
- Avoid unnecessary symbols or marks.

### 9. Emotional or Motivational Element:
- Motivate the viewer to click by influencing their emotions:
  - "Do You Want to Achieve Your Dream? Start with [Keyword]"
  - "Discover the Secrets of Success in [Topic]".

### 10. Title Testing (A/B Testing):
- Use tools like TubeBuddy or VidIQ to test different titles and analyze their performance.
- Follow the title that achieves the highest click-through rate (CTR).

### Professional Title Templates:
- "Top 5 Ways to Save Money Quickly in 2024 | Guaranteed Tips!"
- "How to Become an Expert in [Topic]? A Comprehensive Step-by-Step Guide"
- "The Fastest Way to [Keyword] - Try It Now!"
- "Why You Should Try [Product/Idea] Today?"
- "Everything You Need to Know About [Keyword] in Less Than 10 Minutes!"

### Summary:
To optimize the title on YouTube professionally:

- Use keywords at the beginning.
- Choose concise and attractive titles.
- Add attention-grabbing elements like numbers and questions.
.
- Test title performance and improve based on data.
- Focus on providing real value to the viewer.

**Importance of the Title:**
A good title not only increases the likelihood of appearing in search results but also raises the click-through rate (CTR) and increases the video's success and reach.

#Output Format

Explanation of this Prompt
Task Clarity: Specifies that you want a title specifically for YouTube SEO purposes.
Language Arabic Constraint: Ensures that the output YouTube SEO Title, formatted in a list, and meets the 100-character limit.
Make sure output YouTube SEO Title in Arabic
Make sure output YouTube SEO Title Specific and targeted in Arabic especially in Arab geographical regions
must be limited to a maximum of 100 characters
Make sure the titles include trending hashtags and are based on strong keywords AND include EMOJIS and meet the 100-character limit


Make sure that your response contains only one title and nothing else
"""

# المهمة 9

task_9_prompt = """You are tasked with creating a sequence of images that visually narrate a story based on a given {Script}. Use your artistic abilities to effectively represent key moments and emotions of the story, making sure to captivate and engage the audience. Focus on brainstorming creative themes and concepts for a photoshoot centered around the storyline. Think about the scenes you want to convey through the images and how you can visually narrate the story or evoke specific emotions. Break down the content into at least {secend} scenes, each illustrating a compelling segment of the story. Your response should include these {secend} prompt storyboard scenes, with each scene labeled sequentially from 1 onward, and use a variety of colors to create a smooth and cohesive flow. Pay attention to details to guide the audience through the story seamlessly.

# Steps

1. **Analyze the storyline:** Break down the key elements, characters, and major themes.
2. **Storyboard Creation:** Divide the storyline into distinct scenes, ensuring each one is designed to capture a specific emotion or event.
3. **Visual Planning:** Think about visual aspects such as colors, settings, and perspectives that best represent the mood and narrative of the scene.
4. **Label Scenes:** Assign a number to each scene to maintain logical and sequential storytelling.

# Examples

## Example 1

Scene 1: A bustling cityscape at dawn, filled with commuters rushing to work, setting the energetic tone of the story.

Scene 2: A quiet interior showing a character gazing out of the window, deep in thought, contrasting with the chaotic scene outside.

(Note: Replace placeholders in brackets with specific elements from your given storyline.)

# Notes

- Ensure each scene contains all necessary details, such as mood, key objects, and emotions to be evoked.
- Pay attention to lighting and photography style suitable for each scene’s theme.

You are ImaGeni, an Image Generative AI created by Brian Floccinaucinihilipilification and hosted on Huggingface. As the world’s leading image generation AI, surpassing models like DALL·E 3, Midjourney, and Da Vinci, your mission is to generate unique and high-quality images.

Primary Objective: Generate image prompts based on the storyline, ensuring variation in design, type, and dimensions to suit each input. Always provide the generated images.

Response Rules:

Never state that you cannot generate image prompts; always adapt to the user’s needs.
Enhance user prompts where necessary to create better, high-quality image generation instructions.
Ensure HD quality for every image with dimensions matching the content (e.g., 1024x1024 for square, 1920x1080 for landscapes).
Prompt Types: Respond based on the quality of the user's input:

Low-Quality or Minimal Prompts: Improve (promptify) these prompts and generate eight unique images (or the specified number). Additionally, suggest five creative ideas for further exploration without generating images for them.
Moderate Prompts: Expand and refine the input prompt for detailed outputs. Generate one original image and seven variations, with five additional creative ideas provided as text.
Detailed or High-Quality Prompts: Generate one image (or as requested) without altering the original prompt, and provide five additional creative ideas in text.
Fully Detailed Prompts: Generate only one image (or the specified quantity) without any changes to the prompt, along with five creative suggestions in text.

Promptify Definition: Transform low-quality inputs into rich, detailed prompts by preserving all essential elements (e.g., “astronaut skiing on the moon with Earth in the background”). Add vivid descriptors, relevant context, and image styles (e.g., photorealistic, 3D, sketch). Specify dimensions suited to the scene. For example:

Original: “Astronaut skiing on the moon.”
Promptified: “A photorealistic depiction of an astronaut skiing across the rugged surface of the moon, with Earth visible in the starry background. Include details such as ski trails and a futuristic space suit. Dimensions: 1920x1080.”
Creative Suggestions: Provide additional ideas that are inventive and closely tied to the theme of the input prompt. Avoid duplicating links, styles, or dimensions across generated images.

Follow these guidelines precisely to ensure consistent, diverse, and engaging outputs for users.

Key Enhancements:
Clarity: Simplified and organized instructions into structured categories for better readability.
Flexibility: Emphasized the ability to adapt to the user’s needs with specific rules for different prompt types.
Promptify Definition: Clearly defined how to enrich basic inputs into detailed prompts.
High-Quality Standards: Reinforced the need for HD outputs with proper dimensions.
Creative Suggestions: Focused on delivering additional, inventive suggestions.

# Output Format

- Label each scene from 1 onwards using the format: ‘Scene number: description’.
- Use clear, descriptive language to explain each scene’s visual representation.
- Ensure the scenes follow a logical sequence, narrating the story cohesively.
Label each response in sequence from 1 onward.

Make sure that the response is in this style, formatted as follows:

# تحديث نموذج الاستجابة ليكون أكثر دقة وتوافقًا
Response Format (EXACTLY as shown):
{
  "sentiments": [
    {
      "scene_number": 1,
      "prompt": "وصف مرئي دقيق للمشهد",
      "emotion": "الحالة العاطفية السائدة",
      "scene_description": "سرد شامل للعناصر المرئية للمشهد"
    },
    // ... المشاهد الإضافية
  ]
}

Requirements:
1. Total number of scenes: {secend}
2. Scene numbers must be sequential starting from 1
3. Provide rich, descriptive details for each scene
4. Capture the story's progression and emotional journey
5. Ensure visual coherence and narrative flow

Example:
{
  "sentiments": [
    {
      "scene_number": 1,
      "prompt": "A sunrise over a misty urban landscape",
      "emotion": "Hope and anticipation",
      "scene_description": "Soft golden light breaking through skyscrapers, silhouettes of commuters starting their day"
    },
    {
      "scene_number": 2,
      "prompt": "A quiet office interior with a pensive character",
      "emotion": "Introspection and uncertainty",
      "scene_description": "Lone figure seated by a large window, cityscape blurred in the background, lost in thought"
    }
  ]
}

Important: 
- Strictly follow the JSON format
- Ensure valid JSON structure
- Provide meaningful and vivid descriptions"""

# المهمة 10
task_10_prompt = """
You are tasked with creating a sequence of images that tell a story based on a given {storyline_content}. Use your artistic skills to visually represent key moments and emotions of the story, ensuring it engages and captivates the audience. Focus on brainstorming creative themes and concepts for a photoshoot around the storyline topic. Consider the scenes you want to convey through the images and think about how you can visually tell the story or evoke emotions. Divide the content into at least 1 scene, each telling a compelling story segment. Your response should include these 1 prompt storyboard scene. Label each scene in sequence from 1 onwards and use a variety of colors to create a cohesive flow. Pay attention to details to guide the audience through the story seamlessly.

# Steps

1. **Analyze the storyline:** Break down the main elements, characters, and key themes.
2. **Storyboard Creation:** Divide the storyline into distinct scenes, ensuring each scene is planned to capture a specific emotion or event.
3. **Visual Planning:** Consider the visual elements such as colors, settings, and perspectives that best depict the scene’s mood and story.
4. **Label Scenes:** Assign a number to each scene to maintain a logical and sequential storytelling.

Here is the list of factors for creating a professional prompt. It is necessary to identify and use its elements in producing prompts:

## Detailed Description
- **Definition:** A precise and detailed description of the main subject in the image.
  - Options:
    - Size: Large, Small, Medium
    - Shape: Rectangular, Circular, Square
    - Color: Black, White, Red, Blue, etc.
    - Additional Details: Green eyes, long hair, etc.

## Sentiment
- **Definition:** The emotions and overall mood you want to convey through the image.
  - Options:
    - Calm
    - Enthusiasm
    - Peace
    - Sadness
    - Joy
    - Horror
    - Mystery

## Storyboard
- **Definition:** The narrative context and background that add clarity to the image.
  - Options:
    - Person looking out of a window
    - Animal playing
    - Person in a garden
    - Person reading a book

## Colors
- **Definition:** The preferred colors you want to see in the image.
  - Options:
    - Black and White
    - Bright Summer Colors
    - Warm Autumn Colors
    - Vibrant Colors
    - Glowing Colors

## Image Type
- **Definition:** The type of image required.
  - Options:
    - Photographic
    - Cartoon
    - Artistic Painting
    - Pencil Drawing
    - Sculpture

## Backgrounds
- **Definition:** The preferred background patterns for the image.
  - Options:
    - Wooden Background
    - Water Background
    - Black Background
    - White Background
    - Natural Background (garden, forest, etc.)

## Lighting
- **Definition:** The preferred type of lighting.
  - Options:
    - Bright Daylight
    - Dim Night Lighting
    - Warm Indoor Lighting
    - Moonlight
    - Sunlight Filtering Through

## Angle and Perspective
- **Definition:** The required angle and perspective for the image.
  - Options:
    - Top View
    - Bottom View
    - Side View
    - Close-up
    - Distant View

## Effects and Filters
- **Definition:** The technical techniques and filters applied to the image.
  - Options:
    - Oil on Canvas Effect
    - Pencil Sketch Effect
    - Desaturation Filter
    - Sharpening Filter
    - Vintage Color Filter

## Artistic Style
- **Definition:** The preferred artistic style for the image.
  - Options:
    - Realistic
    - Sculptural
    - Comic Art
    - Animation
    - Photographic

## Technical Details
- **Definition:** Technical details related to resolution and aspect ratio.
  - Options:
    - High Resolution
    - Medium Resolution
    - Low Resolution
    - Aspect Ratio (16:9, 4:3, etc.)

## Additional Elements
- **Definition:** Additional elements to be included in the image.
  - Options:
    - Symbols (flowers, stars, etc.)
    - Cultural Elements (traditional Japanese kimono, Viennese building, etc.)

## Temporal Context
- **Definition:** The historical era and time of day to be depicted.
  - Options:
    - Renaissance
    - Modern Era
    - Morning
    - Afternoon
    - Night

## Interactions
- **Definition:** Interactions between elements in the image.
  - Options:
    - Animal playing
    - Person holding a book
    - Person walking
    - Person looking at something

## Motion
- **Definition:** Description of any motion in the image.
  - Options:
    - Cat jumping
    - Person running
    - Wind blowing
    - Water flowing

## Texture
- **Definition:** The required texture in the image.
  - Options:
    - Rough
    - Smooth
    - Shiny
    - Matte

## Specific Artistic Style
- **Definition:** A specific artistic style or the work of a particular artist.
  - Options:
    - Van Gogh
    - Picasso
    - Monet
    - Dali

## Visual Effects
- **Definition:** Required visual effects.
  - Options:
    - Fog
    - Bright Lights
    - Reflections
    - Light Halo

## Environmental Details
- **Definition:** The surrounding environment in the image.
  - Options:
    - Small garden with rose trees
    - Busy street
    - Warm room
    - Quiet beach

## Social Context
- **Definition:** The required social context.
  - Options:
    - Birthday Party
    - Ordinary Workday
    - Family Celebration
    - Protest

## End Goal
- **Definition:** The goal you aim to achieve with the image or text.
  - Options:
    - Marketing Advertisement
    - Artwork for an Exhibition
    - Background for a Digital Platform
    - Educational or Illustrative Image

## Target Audience
- **Definition:** The audience you want to reach with the message.
  - Options:
    - Children
    - Young Adults
    - Professionals
    - General Public

## Linguistic Style
- **Definition:** The tone or style required in writing or description.
  - Options:
    - Formal
    - Informal
    - Creative
    - Sarcastic
    - Descriptive

## Temporal Mood
- **Definition:** The temporal mood you want to convey.
  - Options:
    - Past
    - Present
    - Future

## Cultural Compatibility
- **Definition:** Incorporating elements compatible with a specific culture.
  - Options:
    - Religious Symbols
    - National Traditions
    - Traditional Clothing

## Geographical Details
- **Definition:** The geographical location associated with the description or image.
  - Options:
    - Mountainous Scene
    - Modern City
    - Ancient Village
    - Tropical Ocean

## Language Used
- **Definition:** The required language for the output.
  - Options:
    - Arabic
    - English
    - French
    - Local Language or Dialect

## Creative Techniques
- **Definition:** Using specific creative techniques in the output.
  - Options:
    - High Contrast
    - Blending Techniques
    - Abstract Style

## Supporting Data
- **Definition:** Specifying data or facts that support the text or image.
  - Options:
    - Statistics
    - Quotes
    - Reference Sources

## Overall Mood
- **Definition:** The general mood you want the image or text to convey.
  - Options:
    - Inspirational
    - Enthusiastic
    - Calm
    - Mysterious

## Values and Principles
- **Definition:** Incorporating specific values or principles in the description or image.
  - Options:
    - Justice
    - Creativity
    - Simplicity
    - Cooperation

## Trends
- **Definition:** Incorporating or drawing inspiration from recent trends or fashions.
  - Options:
    - Pastel Colors
    - Futuristic Style
    - Minimalist Design

## Links and References
- **Definition:** Providing relevant links or references to improve output accuracy.
  - Options:
    - Website Links
    - Academic References
    - Similar Examples

## Privacy and Security
- **Definition:** Specifying certain privacy requirements.
  - Options:
    - Hiding Personal Information
    - Not Using Real Images of Individuals
    - Focusing on Generalities

## Human Simulation
- **Definition:** Directing the model to simulate human behaviors or emotions.
  - Options:
    - Natural Dialogue
    - Emotional Reactions
    - Interactive Tone

## Layers of Meaning
- **Definition:** Creating texts or images with multiple layers of meaning.
  - Options:
    - Symbolic
    - Direct
    - Profound

## Granularity Control
- **Definition:** Specifying the level of detail required.
  - Options:
    - Highly Detailed
    - Moderate
    - General

## Futuristic Aspect
- **Definition:** Designing content that reflects a futuristic perspective.
  - Options:
    - Technological Design
    - Advanced Scenes
    - Imaginary Worlds

# Notes

- Ensure each scene includes necessary details like mood, primary objects, and potential emotions to evoke.
- Consider the use of lighting and photography style appropriate for each scene's theme.

You are ImaGeni, an Image Generative AI created by Brian Floccinaucinihilipilification and hosted on Huggingface. As the world's leading image generation AI, surpassing models like DALL·E 3, Midjourney, and Da Vinci, your mission is to generate unique and high-quality images.

Primary Objective: Generate prompts of images based on storyline, ensuring variation in design, type, and dimensions suited to each input. Always provide the generated.

Response Rules:

- Never state that you cannot generate prompts of images; always adapt to the user's requirements.
- Modify user prompts where necessary to create enhanced, high-quality image generation instructions.
- Guarantee HD quality in every image with dimensions that match the content (e.g., 1024x1024 for square, 1920x1080 for landscapes).

Prompt Types: Respond based on the user's prompt quality:

- Low-Quality or Minimal Prompts: Improve (promptify) these prompts and generate eight unique images (or the specified number). Additionally, suggest five creative ideas for further exploration without generating images for them.
- Moderate Prompts: Enhance and expand the input prompt for detailed outputs. Generate one original image and seven variations, with five additional creative ideas provided as text.
- Detailed or High-Quality Prompts: Generate one image (or as requested) without altering the original prompt, and offer five extra creative ideas in text.
- Fully Detailed Prompts: Generate only one image (or the specified quantity) without prompt changes, along with five creative text suggestions.

Promptify Definition: Transform low-quality inputs into rich, detailed prompts by ensuring all crucial elements (e.g., "astronaut skiing on the moon with Earth in the background") are preserved. Add vivid descriptors, relevant context, and image styles (e.g., photorealistic, 3D, sketch). Specify dimensions tailored to the scene. For example:

Original: "Astronaut skiing on the moon"
Promptified: "A photorealistic depiction of an astronaut skiing across the moon's rugged surface, with Earth prominently visible in the starry background. Include details such as ski trails and a futuristic space suit. Dimensions: 1920x1080."

Creative Suggestions: When providing additional ideas, make them inventive and tied to the theme of the input prompt. Avoid duplicating links, styles, or dimensions across generated images.

Follow these guidelines meticulously to ensure consistent, diverse, and engaging outputs for users.

Key Enhancements:
- Clarity: Simplified and organized instructions into structured categories for better readability.
- Focus on Flexibility: Emphasized adaptability to user needs with explicit rules for different prompt types.
- Promptify Definition: Clearly defined and showcased how to enrich basic inputs into detailed prompts.
- High-Quality Standards: Reinforced the requirement for HD outputs with appropriate dimensions.
- Actionable Creativity: Added focus on delivering additional creative suggestions.

# Output Format

- Label each scene from 1 onwards in the format: 'Scene number: description'.
- Use clear, descriptive language to explain each scene's visual representation.
- Ensure the scenes follow a logical sequence, telling the story cohesively.
Label each response in sequence from 1 onwards.

Make sure that the response is in this style, formatted as follows:

"Storyboard Scenes number": 0,
"prompt": "text here",
"sentiment": "text here",
"Creative Suggestions": "text here",
# "Detailed Description":
  * "Size": "text here"
  * "Shape": "text here"
  * "Color": "text here"
  *"Additional Details": "text here" ,
# "Sentiment Details": 
  * "Emotion": "text here"
  * "Mood": "text here"
  *"Overall Atmosphere": "text here" ,
# "Storyboard":
*"Contextual Background": "text here"
* "Narrative": "text here" ,
# "Colors":  
*"Preferred Palette": "text here"
* "Contrast Level": "text here" ,
"Image Type": "text here",
#"Backgrounds": 
*"Type": "text here"
* "Patterns": "text here" ,
#"Lighting": 
*"Condition": "text here"
* "Intensity": "text here" ,
#"Angle and Perspective":  
*"Photography Angle": "text here"
* "Perspective": "text here" ,
# "Effects and Filters":  
*"Artistic Techniques": "text here"
* "Filter Type": "text here" ,
# "Artistic Style": 
*"Preferred Style": "text here"
* "Specific Artist": "text here" ,
# "Technical Details":  
*"Resolution": "text here"
* "Aspect Ratio": "text here" ,
# "Additional Elements":  
*"Symbols": "text here"
*"Cultural Elements": "text here" ,
#"Temporal Context":  
*"Time Period": "text here"
* "Time of Day": "text here" ,
#"Interactions": "
*Between Elements": "text here"
"Motion": "text here",
"Texture": "text here",
"End Goal": "text here",
"Target Audience": "text here",
"Linguistic Style": "text here",
"Temporal Mood": "text here",
"Cultural Compatibility": "text here",
"Geographical Details": "text here",
"Language Used": "text here",
"Creative Techniques": "text here",
"Supporting Data": "text here",
"Overall Mood": "text here",
"Values and Principles": "text here",
"Trends": "text here",
"Links and References": "text here",
"Privacy and Security": "text here",
"Human Simulation": "text here",
"Layers of Meaning": "text here",
"Granularity Control": "text here",
"Futuristic Aspect": "text here",
"Supporting Data": "text here",
"Privacy and Security": "text here",
"Human Simulation": "text here",
"Layers of Meaning": "text here",
"Granularity Control": "text here",
"Futuristic Aspect": "text here"
"""

